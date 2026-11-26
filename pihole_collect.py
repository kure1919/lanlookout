#!/usr/bin/env python3
"""pihole_collect.py — Pi-hole FTL DB から集計済みクエリ統計を取り出す（読み取り専用）。

監視ホスト側の dns_watch.py が ssh 経由で標準入力に流し込み、各ノード上で実行する。
ノード側にファイルを置く必要はない。

使い方:
  python3 - --db /srv/pi-hole/etc-pihole/pihole-FTL.db --start EPOCH --end EPOCH
  python3 - --db ... --selftest        # スキーマ解決＋実集計の疎通確認
  python3 - --db ... --schema          # 全テーブルとカラムを JSON で出す

出力 (通常モード): JSON 1オブジェクト
  {"pairs":  [[client, domain, count, nx_count, first_ts, last_ts], ...],
   "hourly": [[client, hour_epoch, count, nx_count], ...],
   "client_info": {ip: {"name": DHCPホスト名など, "mac": MACアドレス}, ...}}

FTL v6 (query_storage + domain_by_id / client_by_id) と
v5 (queries テーブル) の両スキーマに対応する。テーブル・カラム・
外部キーは sqlite_master / PRAGMA で全て自動解決する
（カラム名を決め打ちしない）。標準ライブラリのみ。
"""

import argparse
import json
import sqlite3
import sys
import time

# FTL の reply_type: 2 = NXDOMAIN
NXDOMAIN_REPLY_TYPE = 2


def open_db(path):
    """まず読み取り専用で開き、ダメなら通常オープンにフォールバックする。

    WAL モードの DB は読み取り専用接続だと -shm を触れずに失敗することがある。
    その場合でも本スクリプトは SELECT しか発行しないので安全。
    """
    try:
        return sqlite3.connect("file:%s?mode=ro" % path, uri=True)
    except sqlite3.Error:
        db = sqlite3.connect(path)
        # フォールバックでも書き込みはしない。query_only を明示して
        # 「読み取り専用監視」の保証を接続レベルで担保する。
        db.execute("PRAGMA query_only = ON")
        return db


def table_names(db):
    rows = db.execute(
        "SELECT name FROM sqlite_master WHERE type IN ('table', 'view')"
    ).fetchall()
    return {r[0] for r in rows}


def columns(db, table):
    return [r[1] for r in db.execute("PRAGMA table_info(%s)" % table)]


def _text_column(db, table):
    """id 以外で最初のカラムを返す（*_by_id テーブルの文字列カラム推定）。"""
    for c in columns(db, table):
        if c != "id":
            return c
    return "id"


def _fk_column(db, table, by_table):
    """PRAGMA foreign_key_list で by_table を参照すると宣言されたカラム。"""
    try:
        for row in db.execute("PRAGMA foreign_key_list(%s)" % table):
            if row[2] == by_table:  # (id, seq, table, from, to, ...)
                return row[3]
    except sqlite3.Error:
        pass
    return None


def _expr_for(db, table, by_table, candidates, joins, alias):
    """値の式を返す。JOIN が要るスキーマでは JOIN を組み立てる。

    判定の要点: 値カラムそのもの（domain / client）と、ID 参照カラム
    （domain_id / client_id）を取り違えないこと。FTL v6 の
    query_storage は domain / client が TEXT の値そのもので、同時に
    domain_by_id / client_by_id テーブルも存在する。存在だけで JOIN
    すると TEXT 値を INTEGER の id と突き合わせて全行が落ち、
    「収集は成功するのに中身が空」という最悪の形で盲目になる。
    よって JOIN は、FK 宣言があるか、*_id カラムが実在する場合だけ。
    """
    tables = table_names(db)
    cols = set(columns(db, table))
    id_cands = [c for c in candidates if c.endswith("_id")]
    plain = [c for c in candidates if not c.endswith("_id")]
    link = _fk_column(db, table, by_table)
    if link is None:
        link = next((c for c in id_cands if c in cols), None)
    if by_table in tables and link:
        text = _text_column(db, by_table)
        joins.append("JOIN %s %s ON %s.id = q.%s" % (by_table, alias, alias, link))
        return "%s.%s" % (alias, text)
    for cand in plain:
        if cand in cols:
            return "q.%s" % cand
    if link:
        return "q.%s" % link
    raise SystemExit(
        "cannot resolve value column for %s (run with --schema and report the output)"
        % by_table
    )


def resolve_schema(db):
    """集計クエリの部品を解決する。

    戻り値: (from_sql, domain_expr, client_expr, has_reply_type, table)
    """
    tables = table_names(db)
    if "query_storage" in tables:
        qcols = set(columns(db, "query_storage"))
        joins = []
        domain_expr = _expr_for(
            db, "query_storage", "domain_by_id", ("domain_id", "domain"), joins, "d"
        )
        client_expr = _expr_for(
            db, "query_storage", "client_by_id", ("client_id", "client"), joins, "c"
        )
        from_sql = "query_storage q " + " ".join(joins)
        return from_sql, domain_expr, client_expr, ("reply_type" in qcols), "query_storage"
    if "queries" in tables:
        qcols = set(columns(db, "queries"))
        return "queries q", "q.domain", "q.client", ("reply_type" in qcols), "queries"
    raise SystemExit("query table not found: no query_storage / queries table")


def client_info(db):
    """クライアント IP → {name, mac} の対応表（取れる範囲で）。

    FTL v6 の network / network_addresses（DHCP ホスト名と MAC）と、
    client_by_id.name を候補にする。テーブルやカラムが無ければ空で返す
    （本体の集計は止めない）。
    """
    info = {}
    tables = table_names(db)
    if "network_addresses" in tables and "network" in tables:
        try:
            rows = db.execute(
                "SELECT na.ip, na.name, n.hwaddr FROM network_addresses na "
                "JOIN network n ON n.id = na.network_id ORDER BY na.lastSeen"
            ).fetchall()
            for ip, name, mac in rows:
                entry = info.setdefault(ip, {"name": "", "mac": ""})
                if name:
                    entry["name"] = name
                # Docker 版 FTL は LAN の ARP が見えず、MAC 不明の端末には
                # hwaddr に "ip-<アドレス>" という仮置き文字列を入れる。
                # それは MAC ではないので取り込まない。
                if mac and not mac.startswith("ip-"):
                    entry["mac"] = mac
        except sqlite3.Error:
            pass
    if "client_by_id" in tables and "name" in columns(db, "client_by_id"):
        try:
            rows = db.execute("SELECT ip, name FROM client_by_id").fetchall()
            for ip, name in rows:
                if name:
                    info.setdefault(ip, {"name": "", "mac": ""})["name"] = name
        except sqlite3.Error:
            pass
    return info


def collect(db, start, end):
    from_sql, domain_expr, client_expr, has_reply, table = resolve_schema(db)
    nx_expr = (
        "SUM(CASE WHEN q.reply_type = %d THEN 1 ELSE 0 END)" % NXDOMAIN_REPLY_TYPE
        if has_reply
        else "0"
    )
    pairs_sql = """
        SELECT {client}, {domain}, COUNT(*), {nx}, MIN(q.timestamp), MAX(q.timestamp)
        FROM {frm}
        WHERE q.timestamp >= ? AND q.timestamp < ?
        GROUP BY 1, 2
    """.format(client=client_expr, domain=domain_expr, nx=nx_expr, frm=from_sql)
    pairs = [list(r) for r in db.execute(pairs_sql, (start, end)).fetchall()]

    hourly_sql = """
        SELECT {client}, (q.timestamp / 3600) * 3600, COUNT(*), {nx}
        FROM {frm}
        WHERE q.timestamp >= ? AND q.timestamp < ?
        GROUP BY 1, 2
    """.format(client=client_expr, nx=nx_expr, frm=from_sql)
    hourly = [list(r) for r in db.execute(hourly_sql, (start, end)).fetchall()]
    out = {"pairs": pairs, "hourly": hourly, "client_info": client_info(db)}
    warnings = []
    if not has_reply:
        # reply_type が無い DB では NX を数えられない。0 を黙って返すと
        # 「静か」と「測れていない」が区別できなくなるので、警告として
        # 呼び出し側に伝える（NX 系の検知はこのノードでは盲目になる）。
        warnings.append(
            "no reply_type column: NXDOMAIN counts are 0 on this node; "
            "NX-based detection is blind here"
        )
    raw = db.execute(
        "SELECT COUNT(*) FROM %s WHERE timestamp >= ? AND timestamp < ?" % table,
        (start, end),
    ).fetchone()[0]
    if raw > 0 and not pairs:
        # 生行はあるのに集計が空 = スキーマ解決の取り違え等で盲目に
        # なっている疑いが濃い。これも黙らない。
        warnings.append(
            "aggregation produced 0 pairs from %d raw rows in window; "
            "schema resolution may be wrong on this node" % raw
        )
    if warnings:
        out["warnings"] = warnings
    return out


def dump_schema(db):
    return {t: columns(db, t) for t in sorted(table_names(db))}


def selftest(db):
    _from_sql, domain_expr, client_expr, has_reply, table = resolve_schema(db)
    end = int(time.time())
    start = end - 86400
    n = db.execute(
        "SELECT COUNT(*) FROM %s WHERE timestamp >= ? AND timestamp < ?" % table,
        (start, end),
    ).fetchone()[0]
    # 解決した JOIN で実際に集計できることも確認する（selftest の合格条件）
    last_hour = collect(db, end - 3600, end)
    info = last_hour["client_info"]
    named = sum(1 for v in info.values() if v.get("name"))
    maced = sum(1 for v in info.values() if v.get("mac"))
    return {
        "table": table,
        "domain_expr": domain_expr,
        "client_expr": client_expr,
        "has_reply_type": has_reply,
        "queries_last_24h": n,
        "pairs_last_hour": len(last_hour["pairs"]),
        "client_info_entries": len(info),
        "client_info_named": named,
        "client_info_mac": maced,
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--db", required=True)
    ap.add_argument("--start", type=int, default=0)
    ap.add_argument("--end", type=int, default=0)
    ap.add_argument("--selftest", action="store_true")
    ap.add_argument("--schema", action="store_true")
    args = ap.parse_args()

    db = open_db(args.db)
    try:
        if args.schema:
            print(json.dumps(dump_schema(db), ensure_ascii=False))
        elif args.selftest:
            print(json.dumps(selftest(db), ensure_ascii=False))
        else:
            print(json.dumps(collect(db, args.start, args.end)))
    finally:
        db.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
