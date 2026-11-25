#!/usr/bin/env python3
"""dns_watch.py — Pi-hole 2台の DNS クエリを監視ホストに集約し、端末別ベースライン
からの逸脱を検知して Nextcloud Talk に通知する。読み取り専用。

運用型:
  - systemd timer から定期実行
  - 通知に失敗したら state を進めず exit 2（次回リトライ = at-least-once）
  - 重複通知は alerts テーブルの記録で抑止する

検知項目 (v1):
  NEW_PAIR   端末が初めて引いたドメイン（24h 以内に first_seen、24h で 2 回以上）
  NEW_CLIENT ベースラインに無かった端末の出現
  NX_SPIKE   端末の NXDOMAIN 率・件数が平常時から跳ねた（DGA / 設定ミス兆候）
  NIGHT      0–5 時の通信量がその端末の平常夜間から跳ねた

データ取得: ssh で各ノードに pihole_collect.py を流し込み、FTL DB を
読み取りで集計した結果 (JSON) だけを受け取る。ノード側への常駐物はない。

設定は2ファイルに分ける:
  1. dns_watch 固有: ~/.config/lanlookout/config.json
     （環境変数 DNS_WATCH_CONFIG で変更可。読めなければ全項目が既定値）
     キー:
       nodes            対象ノード            既定: ["pihole1", "pihole2"]
       ssh_user         ssh ユーザー          既定: "ansible"
       use_sudo         DB 読み取りに sudo -n を使うか  既定: false
       ftl_db           ノード上の FTL DB パス
                        既定: /srv/pi-hole/etc-pihole/pihole-FTL.db
       state_path       監視ホスト側 state DB のパス
                        既定: ~/.local/state/dns-watch/state.db
                        （git 管理下には置かない。ディレクトリは自動生成）
       ignore_new_pair  NEW_PAIR 検知から外す端末のリスト。
                        ポイ活端末のように毎日新しいドメインを引くのが
                        正常な端末向け。他の検知（NX / 夜間）は効いたまま。
       activeban        activeban への橋渡し設定（任意・既定は無効）。
                        enabled / ssh_host / ssh_key / report_kinds
                        （既定 ["NX_SPIKE"]）/ ttl_seconds / canary。
                        dns_watch は読み取り専用のまま、危険シグナルと
                        カナリアだけを SSH 越しに report する。
  2. Nextcloud 共通: ~/.config/lanlookout/nextcloud.json
     nextcloud_url / talk_token / username / app_password のみを持つ。
     他の監視ツールと共有できる
     （環境変数 DNS_WATCH_NEXTCLOUD_CONFIG で変更可。
       読めなければ Talk には送らず標準出力のみ＝安全側に倒れる）。

使い方:
  dns_watch.py --bootstrap   初回のみ: 過去 30 日で state を種まき（通知しない）
  dns_watch.py --dry-run     検知結果のプレビュー（alerts の抑制を見ず、
                             記録もしない。検証用）
  dns_watch.py --label [IP]  名前解決の確認だけ（検知 state は進めない）
  dns_watch.py               通常実行
"""

import argparse
import base64
import json
import os
import re
import socket
import sqlite3
import subprocess
import sys
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone

JST = timezone(timedelta(hours=9))
HOUR = 3600
DAY = 86400

# ---- 検知の閾値（調整はここ） ----
RECENT_HOURS = 25            # 通常実行で毎回取り直す直近ウィンドウ
BOOTSTRAP_DAYS = 30          # 初回の種まきで遡る日数
NEW_PAIR_MIN_COUNT = 2       # 新規ドメインとみなす 24h 最低回数
NEW_PAIR_MAX_PER_CLIENT = 8  # 通知に列挙するドメイン数の上限/端末
NX_MIN_COUNT = 50            # NXDOMAIN 急増とみなす 24h 最低件数
NX_MIN_RATIO = 0.35          # NXDOMAIN 急増とみなす 24h 最低率
NX_BASELINE_FACTOR = 3.0     # 平常率の何倍で急増とするか
NIGHT_MIN_COUNT = 100        # 夜間急増とみなす 0–5 時の最低件数
NIGHT_FACTOR = 1.5           # 過去夜間の最大値の何倍で「前例のない夜」とするか
NIGHT_MIN_NIGHTS = 5         # 判定に必要な過去夜間のサンプル数
ALERT_SUPPRESS_DAYS = 7      # 同一所見の再通知を抑える日数
SELF_IPS = {"127.0.0.1", "::1"}  # リゾルバ自身は検知対象にしない

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
COLLECTOR = os.path.join(SCRIPT_DIR, "pihole_collect.py")

def _default_config_path():
    return os.path.expanduser("~/.config/lanlookout/config.json")


CONFIG_PATH = os.environ.get("DNS_WATCH_CONFIG") or _default_config_path()


def _load_config():
    """dns_watch 専用 config.json を読む。無ければ全項目が既定値。

    ただし「ファイルはあるが JSON として壊れている」場合は既定値で
    黙って走らない。ノード名等が既定に落ちて無関係な所で落ちるより、
    設定の構文エラーをその場で明示して止まる方が正しい。
    """
    cfg = {}
    if os.path.exists(CONFIG_PATH):
        try:
            with open(CONFIG_PATH, encoding="utf-8") as f:
                cfg = json.load(f)
        except Exception as e:
            raise SystemExit(
                "dns_watch: config が読めない (%s): %s" % (CONFIG_PATH, e)
            )
    return {
        "nodes": cfg.get("nodes", ["pihole1", "pihole2"]),
        "ssh_user": cfg.get("ssh_user", "ansible"),
        "use_sudo": bool(cfg.get("use_sudo", False)),
        "ftl_db": cfg.get("ftl_db", "/srv/pi-hole/etc-pihole/pihole-FTL.db"),
        "state_path": os.environ.get(
            "DNS_WATCH_STATE",
            os.path.expanduser(cfg.get("state_path", "~/.local/state/dns-watch/state.db")),
        ),
        "ignore_new_pair": set(cfg.get("ignore_new_pair", [])),
        # NEW_PAIR から外すドメイン族。"*.example.com" で配下すべて、
        # 素の文字列で完全一致。ローテーションするホスト名用。
        "ignore_domain_patterns": [
            str(x).lower() for x in cfg.get("ignore_domain_patterns", [])
        ],
        # 行動系の検知（NEW_PAIR / NX_SPIKE / NIGHT）を丸ごと外す端末。
        # NEW_CLIENT には効かせない（除外した IP を別端末が拾ったら知りたい）。
        "ignore_clients": set(cfg.get("ignore_clients", [])),
        # 端末名の手動マップ (MAC or IP -> 名前) の置き場所。
        # FTL は DHCP サーバーではないのでホスト名をほぼ学習できない。
        # 一度同定した端末はここに書けば通知にその名前が出る。
        "device_names_path": os.path.expanduser(
            cfg.get("device_names_path", "~/.config/lanlookout/device_names.json")
        ),
        # 監視ホスト自身の ARP テーブルから IP->MAC を学習する。
        # Docker 版 FTL からは実 MAC が見えないための代替経路。
        "arp_learn": bool(cfg.get("arp_learn", True)),
        # 学習の前に自ネットへ UDP プローブを送って ARP テーブルを温める。
        "arp_sweep": bool(cfg.get("arp_sweep", True)),
        # NEW_PAIR は「宛先集合が小さい機器らしいクライアント」にだけ適用する。
        # 30日間の宛先ペア数がこれを超えるクライアントは人間の端末とみなして
        # 除外する（人間は毎日100件以上の新規ドメインを踏むので検知にならない）。
        "new_pair_max_client_pairs": int(cfg.get("new_pair_max_client_pairs", 400)),
        # activeban への橋渡し（任意・既定は無効）。dns_watch は読み取り
        # 専用のまま、危険シグナルだけを SSH forced-command 経由で
        # activeban に report する。NEW_PAIR / NEW_CLIENT は発見
        # シグナルなので report 対象にしない（自動バンの契機にしない）。
        "activeban": _activeban_config(cfg.get("activeban") or {}),
    }


def _activeban_config(ab):
    return {
        "enabled": bool(ab.get("enabled", False)),
        # 例: "qdetect@nemesis"。forced-command キー前提。
        "ssh_host": ab.get("ssh_host", ""),
        "ssh_key": ab.get("ssh_key", ""),
        # テスト/同一ホスト用に ssh の代わりのコマンド列を指定できる。
        "command": ab.get("command"),
        "report_kinds": list(ab.get("report_kinds", ["NX_SPIKE"])),
        "ttl_seconds": int(ab.get("ttl_seconds", 21600)),
        "canary": bool(ab.get("canary", True)),
        "canary_ttl_seconds": int(ab.get("canary_ttl_seconds", 300)),
    }


CONFIG = _load_config()


# ---------------------------------------------------------------- 収集
def collect(node, start, end):
    """ssh 経由でノード上の FTL DB を集計し、dict で返す。失敗時は例外。"""
    remote = [
        "python3", "-",
        "--db", CONFIG["ftl_db"],
        "--start", str(start), "--end", str(end),
    ]
    if CONFIG["use_sudo"]:
        remote = ["sudo", "-n"] + remote
    cmd = [
        "ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10",
        "%s@%s" % (CONFIG["ssh_user"], node),
    ] + remote
    with open(COLLECTOR, "rb") as f:
        src = f.read()
    p = subprocess.run(cmd, input=src, capture_output=True, timeout=900)
    if p.returncode != 0:
        raise RuntimeError(
            "collect failed on %s: %s" % (node, p.stderr.decode("utf-8", "replace")[:500])
        )
    return json.loads(p.stdout.decode("utf-8"))


# ---------------------------------------------------------------- state
SCHEMA = """
CREATE TABLE IF NOT EXISTS pairs (
  client TEXT, domain TEXT, first_seen INTEGER, last_seen INTEGER,
  recent_count INTEGER, PRIMARY KEY (client, domain)
);
CREATE TABLE IF NOT EXISTS hourly (
  client TEXT, hour INTEGER, count INTEGER, nx INTEGER,
  PRIMARY KEY (client, hour)
);
CREATE TABLE IF NOT EXISTS clients (
  client TEXT PRIMARY KEY, first_seen INTEGER
);
CREATE TABLE IF NOT EXISTS alerts (
  client TEXT, kind TEXT, akey TEXT, ts INTEGER,
  PRIMARY KEY (client, kind, akey)
);
CREATE TABLE IF NOT EXISTS ip_mac (
  ip TEXT PRIMARY KEY, mac TEXT, first_seen INTEGER, last_seen INTEGER
);
CREATE TABLE IF NOT EXISTS ip_mac_history (
  ip TEXT, mac TEXT, valid_from INTEGER, valid_to INTEGER,
  PRIMARY KEY (ip, mac, valid_from)
);
CREATE TABLE IF NOT EXISTS id_clients (
  identity TEXT PRIMARY KEY, first_seen INTEGER
);
CREATE TABLE IF NOT EXISTS id_pairs (
  identity TEXT, domain TEXT, first_seen INTEGER, last_seen INTEGER,
  recent_count INTEGER, PRIMARY KEY (identity, domain)
);
"""


def collect_all(start, end):
    """全ノード分を収集し、メモリ上で合算してから返す。

    ノードごとに state へ書くと、同一 (client, hour) の行が後勝ちで
    上書きされ、片方のノードの分しか残らない。必ず先に合算すること。
    1台でも収集に失敗したら例外（state は進めない）。
    """
    pairs = {}   # (client, domain) -> [count, nx, first_ts, last_ts]
    hourly = {}  # (client, hour) -> [count, nx]
    info = {}    # client ip -> {"name": ..., "mac": ...}
    for node in CONFIG["nodes"]:
        data = collect(node, start, end)
        for ip, entry in (data.get("client_info") or {}).items():
            cur = info.setdefault(ip, {"name": "", "mac": ""})
            if entry.get("name"):
                cur["name"] = entry["name"]
            if entry.get("mac"):
                cur["mac"] = entry["mac"]
        for client, domain, count, nx, first_ts, last_ts in data["pairs"]:
            cur = pairs.get((client, domain))
            if cur is None:
                pairs[(client, domain)] = [count, nx, first_ts, last_ts]
            else:
                cur[0] += count
                cur[1] += nx
                cur[2] = min(cur[2], first_ts)
                cur[3] = max(cur[3], last_ts)
        for client, hour, count, nx in data["hourly"]:
            cur = hourly.get((client, hour))
            if cur is None:
                hourly[(client, hour)] = [count, nx]
            else:
                cur[0] += count
                cur[1] += nx
    return {"pairs": pairs, "hourly": hourly, "client_info": info}


# ---------------------------------------------------------------- ARP 学習
# Docker 版 FTL からは LAN の実 MAC が見えない（hwaddr は "ip-..." の仮置き）。
# 監視ホストは LAN 内にいるので、自ホストの neighbor テーブルから IP->MAC を学ぶ。
_MAC_RE = re.compile(r"^[0-9a-f]{2}(:[0-9a-f]{2}){5}$")


def _neigh_table():
    """`ip neigh show` を {ip: mac} にして返す（IPv4 のみ、lladdr がある行だけ）。"""
    result = {}
    try:
        out = subprocess.run(
            ["ip", "neigh", "show"], capture_output=True, text=True, timeout=30
        ).stdout
    except Exception:
        return result
    for line in out.splitlines():
        parts = line.split()
        if not parts or ":" in parts[0] or "lladdr" not in parts:
            continue
        mac = parts[parts.index("lladdr") + 1].lower()
        if _MAC_RE.match(mac):
            result[parts[0]] = mac
    return result


def _self_table():
    """自ホスト自身の {ip: mac} を返す。

    neighbor テーブルには自分の IP は載らない（自分宛に ARP しない）ため、
    ARP 学習だけでは 監視ホスト自身の MAC が永遠に引けない。そこで自インター
    フェースのアドレス情報から直接取る。IP が変わっても実行時の実値で
    追随するので、静的な IP キーのような腐り方はしない。
    """
    result = {}
    try:
        out = subprocess.run(
            ["ip", "-j", "addr"], capture_output=True, text=True, timeout=30
        ).stdout
        for iface in json.loads(out):
            mac = (iface.get("address") or "").lower()
            if not _MAC_RE.match(mac) or mac == "00:00:00:00:00:00":
                continue
            for info in iface.get("addr_info", []):
                if info.get("family") != "inet":
                    continue
                local = info.get("local", "")
                if local and not local.startswith("127."):
                    result[local] = mac
        if result:
            return result
    except Exception:
        pass
    # フォールバック: -j が使えない環境ではテキスト形式から拾う
    try:
        link_out = subprocess.run(
            ["ip", "-o", "link", "show"], capture_output=True, text=True, timeout=30
        ).stdout
        iface_mac = {}
        for line in link_out.splitlines():
            m = re.match(r"\d+:\s+([^:@]+)[^:]*:\s+.*link/ether\s+([0-9a-f:]{17})", line)
            if m:
                iface_mac[m.group(1)] = m.group(2).lower()
        addr_out = subprocess.run(
            ["ip", "-o", "-4", "addr", "show"],
            capture_output=True, text=True, timeout=30,
        ).stdout
        for line in addr_out.splitlines():
            parts = line.split()
            if len(parts) < 4:
                continue
            ip = None
            for i, p in enumerate(parts):
                if p == "inet" and i + 1 < len(parts):
                    ip = parts[i + 1].split("/")[0]
                    break
            iface = parts[1] if len(parts) > 1 else ""
            if ip and not ip.startswith("127.") and iface in iface_mac:
                if iface_mac[iface] != "00:00:00:00:00:00":
                    result[ip] = iface_mac[iface]
    except Exception:
        pass
    return result


def _local_sweep_targets():
    """自ホストの IPv4 が属する /24 のホストアドレス一覧（スイープ用）。"""
    locals_ = []
    try:
        out = subprocess.run(
            ["ip", "-j", "addr"], capture_output=True, text=True, timeout=30
        ).stdout
        for iface in json.loads(out):
            for info in iface.get("addr_info", []):
                if info.get("family") == "inet":
                    locals_.append(info.get("local", ""))
    except Exception:
        pass
    if not locals_:
        # 古い iproute2 等で -j が使えない場合のフォールバック（テキスト形式）
        try:
            out = subprocess.run(
                ["ip", "-o", "-4", "addr", "show"],
                capture_output=True, text=True, timeout=30,
            ).stdout
            locals_ = re.findall(r"inet (\d+\.\d+\.\d+\.\d+)/", out)
        except Exception:
            pass
    targets = set()
    for local in locals_:
        if not local or local.startswith("127."):
            continue
        base = ".".join(local.split(".")[:3])
        targets.update("%s.%d" % (base, i) for i in range(1, 255))
    return sorted(targets)


def _probe(ip):
    """対象へ UDP を1発送る。IP パケットを送れば ARP 解決が走るので、
    相手が何も返さなくても neighbor テーブルに MAC が載る。
    ping と違い特権も外部コマンドも要らない。"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.sendto(b"\x00", (ip, 9))
        finally:
            s.close()
    except Exception:
        pass


def learn_ip_mac(sweep=True):
    """IP->MAC を学ぶ。失敗しても例外にせず、取れた分だけ返す。

    sweep=True なら自ネット /24 に UDP プローブを送って ARP テーブルを
    温めてから読む（ARP 解決の完了を少し待って2回読んで union する）。
    寝ている端末はテーブルに載らないことがある（その分は次回以降に期待）。
    """
    try:
        if sweep:
            targets = _local_sweep_targets()
            if targets:
                with ThreadPoolExecutor(max_workers=32) as ex:
                    list(ex.map(_probe, targets))
                first = _neigh_table()
                time.sleep(2)
                table = _neigh_table()
                table.update(first)
            else:
                table = _neigh_table()
        else:
            table = _neigh_table()
    except Exception:
        table = {}
    # 自ホスト分は neighbor に載らないので別経路で補う（自情報が正なので優先）
    try:
        table.update(_self_table())
    except Exception:
        pass
    return table


# ---------------------------------------------------------------- 同一性 (identity)
# 端末の同一性は MAC を主キーにする: identity は "mac:<mac>"、MAC が
# 分からない端末は IP 文字列そのもの。DHCP で IP が移っても同一性は
# 変わらないので、宛先履歴やベースラインを MAC 軸で追える。
# ip_mac_history が「どの IP を・いつからいつまで・どの MAC が持って
# いたか」の区間を持つ。区間の境界は検出タイミングではなく「旧 MAC を
# 最後に確認した時刻」に置く（引っ越しの実時刻はその直後のはずで、
# 新しい持ち主の最初のクエリは必ず境界より後になるため）。


def _record_ip_mac(conn, ip, mac, now):
    """ip_mac の更新と ip_mac_history の区間維持をまとめて行う。

    MAC が変わっていたら旧区間を閉じて新区間を開く。端末の同一性が
    IP キーから MAC キーへ初めて昇格する場合は、IP キーで溜まっていた
    id_pairs / id_clients を MAC 側へ引き継ぐ（履歴の孤児化防止）。
    """
    mac = (mac or "").lower()
    if not _MAC_RE.match(mac):
        return
    prev = conn.execute(
        "SELECT mac, last_seen FROM ip_mac WHERE ip = ?", (ip,)
    ).fetchone()
    prev_mac = (prev[0] or "").lower() if prev else ""
    conn.execute(
        """
        INSERT INTO ip_mac (ip, mac, first_seen, last_seen) VALUES (?, ?, ?, ?)
        ON CONFLICT (ip) DO UPDATE SET
          mac = excluded.mac,
          first_seen = MIN(first_seen, excluded.first_seen),
          last_seen = excluded.last_seen
        """,
        (ip, mac, now, now),
    )
    if prev_mac == mac:
        return
    boundary = prev[1] if prev and prev[1] else now
    open_row = conn.execute(
        "SELECT mac, valid_from FROM ip_mac_history "
        "WHERE ip = ? AND valid_to IS NULL ORDER BY valid_from DESC LIMIT 1",
        (ip,),
    ).fetchone()
    if open_row and open_row[0] != mac:
        conn.execute(
            "UPDATE ip_mac_history SET valid_to = ? WHERE ip = ? AND valid_from = ?",
            (boundary, ip, open_row[1]),
        )
    if not open_row or open_row[0] != mac:
        conn.execute(
            "INSERT OR IGNORE INTO ip_mac_history (ip, mac, valid_from, valid_to) "
            "VALUES (?, ?, ?, NULL)",
            (ip, mac, boundary if prev_mac else now),
        )
    if not prev_mac:
        # 同一性の昇格: IP キーの履歴を MAC キーへ寄せる
        new_id = "mac:" + mac
        for (domain, f, l, c) in conn.execute(
            "SELECT domain, first_seen, last_seen, recent_count FROM id_pairs "
            "WHERE identity = ?",
            (ip,),
        ).fetchall():
            conn.execute(
                """
                INSERT INTO id_pairs (identity, domain, first_seen, last_seen, recent_count)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT (identity, domain) DO UPDATE SET
                  first_seen = MIN(first_seen, excluded.first_seen),
                  last_seen = MAX(last_seen, excluded.last_seen),
                  recent_count = MAX(recent_count, excluded.recent_count)
                """,
                (new_id, domain, f, l, c),
            )
        conn.execute("DELETE FROM id_pairs WHERE identity = ?", (ip,))
        row = conn.execute(
            "SELECT first_seen FROM id_clients WHERE identity = ?", (ip,)
        ).fetchone()
        if row:
            conn.execute(
                """
                INSERT INTO id_clients (identity, first_seen) VALUES (?, ?)
                ON CONFLICT (identity) DO UPDATE SET
                  first_seen = MIN(first_seen, excluded.first_seen)
                """,
                (new_id, row[0]),
            )
            conn.execute("DELETE FROM id_clients WHERE identity = ?", (ip,))


def _identity_at(conn, ip, ts):
    """時刻 ts にその IP を持っていた端末の identity を返す。

    区間に ts が含まれる持ち主が正。区間の隙間（引っ越し直後など）に
    落ちた場合は次の持ち主を採る — 隙間に現れるクエリは、去った端末
    ではなく来た端末のものと考える方が自然なため。
    """
    rows = conn.execute(
        "SELECT mac, valid_from, valid_to FROM ip_mac_history "
        "WHERE ip = ? ORDER BY valid_from",
        (ip,),
    ).fetchall()
    for mac, vf, vt in rows:
        if vf <= ts and (vt is None or ts < vt):
            return "mac:" + mac
    for mac, vf, vt in rows:
        if vf > ts:
            return "mac:" + mac
    if rows:
        return "mac:" + rows[-1][0]
    row = conn.execute("SELECT mac FROM ip_mac WHERE ip = ?", (ip,)).fetchone()
    if row and row[0] and _MAC_RE.match(row[0].lower()):
        return "mac:" + row[0].lower()
    return ip


def _identity_ips(conn, identity):
    """identity が現在使っている（使っていた）IP の一覧。"""
    if identity.startswith("mac:"):
        return [
            ip for (ip,) in conn.execute(
                "SELECT ip FROM ip_mac WHERE mac = ?", (identity[4:],)
            ).fetchall()
        ]
    return [identity]


def _identity_known_since(conn, identity):
    """その MAC が最初に観測された時刻。MAC identity でなければ None。"""
    if not identity.startswith("mac:"):
        return None
    mac = identity[4:]
    vals = []
    row = conn.execute(
        "SELECT MIN(valid_from) FROM ip_mac_history WHERE mac = ?", (mac,)
    ).fetchone()
    if row and row[0] is not None:
        vals.append(row[0])
    row = conn.execute(
        "SELECT MIN(first_seen) FROM ip_mac WHERE mac = ?", (mac,)
    ).fetchone()
    if row and row[0] is not None:
        vals.append(row[0])
    return min(vals) if vals else None


def merge(conn, combined, learned=None, now=0):
    """合算済みの収集結果を state に取り込む。

    hourly は「その時間帯の確定値」として置き換える。再収集した時間帯は
    合算済みの値で上書きされるので、二重数えにはならない。
    あわせて同一性（MAC 主キー）軸の id_pairs / id_clients を維持する。
    帰属は ip_mac_history の区間で決めるので、IP が移っても履歴は
    MAC 側に残り続ける。
    """
    # ARP 学習分を先に取り込む（同一性の判定材料を最新にしてから帰属する）
    for ip, mac in (learned or {}).items():
        _record_ip_mac(conn, ip, mac, now)
    id_agg = {}
    for (client, domain), (count, _nx, first_ts, last_ts) in combined["pairs"].items():
        ident = _identity_at(conn, client, first_ts)
        a = id_agg.setdefault((ident, domain), [0, first_ts, last_ts])
        a[0] += count
        a[1] = min(a[1], first_ts)
        a[2] = max(a[2], last_ts)
        conn.execute(
            """
            INSERT INTO pairs (client, domain, first_seen, last_seen, recent_count)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT (client, domain) DO UPDATE SET
              first_seen = MIN(first_seen, excluded.first_seen),
              last_seen = MAX(last_seen, excluded.last_seen),
              recent_count = excluded.recent_count
            """,
            (client, domain, first_ts, last_ts, count),
        )
        conn.execute(
            """
            INSERT INTO clients (client, first_seen) VALUES (?, ?)
            ON CONFLICT (client) DO UPDATE SET
              first_seen = MIN(first_seen, excluded.first_seen)
            """,
            (client, first_ts),
        )
    for (ident, domain), (count, first_ts, last_ts) in id_agg.items():
        conn.execute(
            """
            INSERT INTO id_pairs (identity, domain, first_seen, last_seen, recent_count)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT (identity, domain) DO UPDATE SET
              first_seen = MIN(first_seen, excluded.first_seen),
              last_seen = MAX(last_seen, excluded.last_seen),
              recent_count = excluded.recent_count
            """,
            (ident, domain, first_ts, last_ts, count),
        )
        conn.execute(
            """
            INSERT INTO id_clients (identity, first_seen) VALUES (?, ?)
            ON CONFLICT (identity) DO UPDATE SET
              first_seen = MIN(first_seen, excluded.first_seen)
            """,
            (ident, first_ts),
        )
    for (client, hour), (count, nx) in combined["hourly"].items():
        conn.execute(
            "INSERT OR REPLACE INTO hourly (client, hour, count, nx) VALUES (?, ?, ?, ?)",
            (client, hour, count, nx),
        )
    # 端末の名前/MAC は取れた分だけ clients に反映する（行がある端末のみ）
    for ip, entry in (combined.get("client_info") or {}).items():
        if entry.get("name"):
            conn.execute(
                "UPDATE clients SET name = ? WHERE client = ?", (entry["name"], ip)
            )
        if entry.get("mac"):
            conn.execute(
                "UPDATE clients SET mac = ? WHERE client = ?", (entry["mac"], ip)
            )
    # FTL の仮置き文字列（ip-...）が MAC 欄に入り込んでいたら掃除する
    conn.execute("UPDATE clients SET mac = NULL WHERE mac LIKE 'ip-%'")
    # clients.mac へ同期する（実 MAC の正は ip_mac。取り込みは冒頭で済み）
    conn.execute(
        """
        UPDATE clients SET mac = (
          SELECT mac FROM ip_mac WHERE ip_mac.ip = clients.client
        ) WHERE client IN (SELECT ip FROM ip_mac)
        """
    )


DEVICE_NAMES = {}


def _load_device_names():
    """手動マップを読む。キーは MAC（大文字化して照合）または IP。"""
    try:
        with open(CONFIG["device_names_path"], encoding="utf-8") as f:
            raw = json.load(f)
    except Exception:
        return {}
    names = {}
    for key, value in raw.items():
        if isinstance(value, str) and value:
            names[key.upper()] = value
    return names


def client_label(conn, client):
    """通知用の端末表記: 'IP (名前, MAC)'。

    名前の優先順位: 手動マップ（MAC キー → IP キー）> FTL が知っている名前。
    """
    row = conn.execute(
        "SELECT name, mac FROM clients WHERE client = ?", (client,)
    ).fetchone()
    ftl_name = (row[0] or "") if row else ""
    mac = (row[1] or "") if row else ""
    # FTL の自動仮名（ip-<自IP>）や MAC そのままの名前は「名前なし」として扱う
    if ftl_name == "ip-" + client or (mac and ftl_name.upper() == mac.upper()):
        ftl_name = ""
    # MAC 欄に入った仮置き文字列（ip-...）も MAC として扱わない
    if mac.startswith("ip-"):
        mac = ""
    friendly = ""
    if mac:
        friendly = DEVICE_NAMES.get(mac.upper(), "")
    if not friendly:
        friendly = DEVICE_NAMES.get(client.upper(), "")
    if not friendly:
        friendly = ftl_name or ""
    extras = []
    if friendly:
        extras.append(friendly)
    if mac:
        extras.append(mac)
    return client + (" (%s)" % ", ".join(extras) if extras else "")


def identity_label(conn, identity):
    """identity 用の通知表記。MAC identity は代表 IP のラベルで出す。"""
    if identity.startswith("mac:"):
        row = conn.execute(
            "SELECT ip FROM ip_mac WHERE mac = ? ORDER BY last_seen DESC LIMIT 1",
            (identity[4:],),
        ).fetchone()
        if row:
            return client_label(conn, row[0])
        mac = identity[4:]
        friendly = DEVICE_NAMES.get(mac.upper(), "")
        extras = ", ".join(x for x in (friendly, mac) if x)
        return "mac:" + mac + (" (%s)" % extras if extras else "")
    return client_label(conn, identity)


def _identity_matches_ips(conn, identity, ips):
    """identity が IP リスト（ignore 系 config）に該当するか。"""
    if identity in ips:
        return True
    return any(ip in ips for ip in _identity_ips(conn, identity))


# ---------------------------------------------------------------- 検知
# dry-run（プレビュー）では True の間だけ alerts テーブルによる抑制を効かせる。
# 検証したい時に本番の抑制に邪魔されないよう、run() が dry_run で切り替える。
HONOR_ALERTS = True


def already_alerted(conn, client, kind, akey, now, days=ALERT_SUPPRESS_DAYS):
    if not HONOR_ALERTS:
        return False
    row = conn.execute(
        "SELECT ts FROM alerts WHERE client = ? AND kind = ? AND akey = ?",
        (client, kind, akey),
    ).fetchone()
    return row is not None and row[0] >= now - days * DAY


def record_alert(conn, client, kind, akey, now):
    conn.execute(
        "INSERT OR REPLACE INTO alerts (client, kind, akey, ts) VALUES (?, ?, ?, ?)",
        (client, kind, akey, now),
    )


def _defang(domain):
    """通知文中のドメインをリンク化されない形（[.] 置換）にする。

    Nextcloud Talk のクライアント（iOS で実証、2026-11-16）がメッセージ中の
    ベアドメインをリンクと解釈し、サーバー側リンクプレビューがそのドメインを
    取得しに行く。監視通知に載ったドメインを監視対象のサーバー自身が踏む
    自己言及ループ（リゾルバ自身の名義で出る幽霊 findings）の再発防止と、
    本当に悪性のドメインをサーバーが自動取得する事故の防止のため、表示だけ
    defang する。判定・記録・抑制は元のドメイン文字列のまま扱う。
    """
    return domain.replace(".", "[.]")


def _domain_ignored(domain):
    """config の ignore_domain_patterns にマッチするか。

    "*.example.com" は example.com 配下すべて（自身を含む）に、
    素の文字列は完全一致にマッチする。ホスト名の一部がローテーションする
    インフラ（Delivery Optimization 等）を族ごと外すためのもの。
    NEW_PAIR にだけ効く（NX_SPIKE / NIGHT には効かない）。
    """
    for pat in CONFIG["ignore_domain_patterns"]:
        if pat.startswith("*."):
            suffix = pat[2:]
            if domain == suffix or domain.endswith("." + suffix):
                return True
        elif domain == pat:
            return True
    return False


def check_new_pairs(conn, now, skip_identities=frozenset()):
    """NEW_PAIR は同一性（MAC 主キー）軸で判定する。

    id_pairs は端末の全 IP 時代を通した履歴なので、DHCP の引っ越しや
    使い回し IP への移動では、既知の宛先が「新規」に化けることはない。
    """
    findings = []  # (identity, kind, akey, text)
    rows = conn.execute(
        """
        SELECT identity, domain, recent_count FROM id_pairs
        WHERE first_seen >= ? AND recent_count >= ?
          AND domain LIKE '%.%'
          AND (SELECT COUNT(*) FROM id_pairs q WHERE q.identity = id_pairs.identity) <= ?
        ORDER BY identity, recent_count DESC
        """,
        (now - DAY, NEW_PAIR_MIN_COUNT, CONFIG["new_pair_max_client_pairs"]),
    ).fetchall()
    by_id = {}
    for ident, domain, count in rows:
        by_id.setdefault(ident, []).append((domain, count))
    for ident, items in sorted(by_id.items()):
        if ident in skip_identities:
            continue
        if _identity_matches_ips(conn, ident, CONFIG["ignore_new_pair"]):
            continue
        fresh = [
            (d, c) for d, c in items
            if not _domain_ignored(d)
            and not already_alerted(conn, ident, "NEW_PAIR", d, now)
        ]
        if not fresh:
            continue
        shown = fresh[:NEW_PAIR_MAX_PER_CLIENT]
        text = "、".join("%s (%d回)" % (_defang(d), c) for d, c in shown)
        if len(fresh) > len(shown):
            text += " ほか%d件" % (len(fresh) - len(shown))
        findings.append((ident, "NEW_PAIR", [d for d, _ in fresh],
                         "■ 新規宛先 %s: %s" % (identity_label(conn, ident), text)))
    return findings


def known_released_identities(conn, now):
    """同一性は新しいが MAC 自体は既知（1時間以上前から観測）の集合。

    MAC の初観測が遅れた古い端末が同一性として新規に現れた場合の
    NEW_PAIR 初回抑制用（従来のリース替え抑制の同一性版）。
    """
    out = set()
    rows = conn.execute(
        "SELECT identity FROM id_clients WHERE first_seen >= ?", (now - DAY,)
    ).fetchall()
    for (ident,) in rows:
        since = _identity_known_since(conn, ident)
        if since is not None and since <= now - HOUR:
            out.add(ident)
    return out


def check_new_clients(conn, now):
    findings = []
    rows = conn.execute(
        "SELECT identity FROM id_clients WHERE first_seen >= ?", (now - DAY,)
    ).fetchall()
    for (ident,) in rows:
        # MAC が1時間以上前から既知なら、IP が変わっただけの既知端末
        since = _identity_known_since(conn, ident)
        if since is not None and since <= now - HOUR:
            continue
        if already_alerted(conn, ident, "NEW_CLIENT", ident, now, days=30):
            continue
        findings.append((ident, "NEW_CLIENT", [ident],
                         "■ 新規クライアント %s" % identity_label(conn, ident)))
    return findings


def _id_hourly_series(conn):
    """hourly（IP キー）を同一性軸に読み替えた {identity: {hour: [count, nx]}}。

    帰属は ip_mac_history の区間で決める。保存済みテーブルではなく
    読み替えで済ませるので、履歴が後から育っても過去分まで一貫する。
    """
    series = {}
    cache = {}
    rows = conn.execute("SELECT client, hour, count, nx FROM hourly").fetchall()
    for client, hour, count, nx in rows:
        key = (client, hour)
        ident = cache.get(key)
        if ident is None:
            ident = _identity_at(conn, client, hour)
            cache[key] = ident
        per = series.setdefault(ident, {})
        a = per.setdefault(hour, [0, 0])
        a[0] += count
        a[1] += nx
    return series


def _series_sums(per, start, end):
    c = n = 0
    for hour, (count, nx) in per.items():
        if start <= hour < end:
            c += count
            n += nx
    return c, n


def check_nx_spike(conn, now):
    findings = []
    series = _id_hourly_series(conn)
    identities = [r[0] for r in conn.execute("SELECT identity FROM id_clients").fetchall()]
    for ident in identities:
        per = series.get(ident, {})
        c1, n1 = _series_sums(per, now - DAY, now)
        if c1 == 0 or n1 < NX_MIN_COUNT:
            continue
        ratio1 = n1 / c1
        if ratio1 < NX_MIN_RATIO:
            continue
        c0, n0 = _series_sums(per, now - 14 * DAY, now - DAY)
        ratio0 = (n0 / c0) if c0 else 0.0
        if n0 >= 10 and ratio1 < NX_BASELINE_FACTOR * ratio0:
            continue
        akey = datetime.fromtimestamp(now, JST).strftime("%Y-%m-%d")
        if already_alerted(conn, ident, "NX_SPIKE", akey, now, days=1):
            continue
        findings.append((ident, "NX_SPIKE", [akey],
                         "■ NXDOMAIN急増 %s: 24hで %d件 (率 %.0f%%、平常 %.0f%%)"
                         % (identity_label(conn, ident), n1, ratio1 * 100, ratio0 * 100)))
    return findings


def _night_window(day):
    """JST の day 00:00–05:00 の (start, end) epoch。"""
    start = datetime(day.year, day.month, day.day, 0, 0, tzinfo=JST)
    return int(start.timestamp()), int((start + timedelta(hours=5)).timestamp())


def check_night(conn, now):
    findings = []
    now_jst = datetime.fromtimestamp(now, JST)
    if now_jst.hour < 6:
        return findings  # 夜間が終わるまでは判定しない
    today = now_jst.date()
    start, end = _night_window(today)
    series = _id_hourly_series(conn)
    identities = [r[0] for r in conn.execute("SELECT identity FROM id_clients").fetchall()]
    for ident in identities:
        per = series.get(ident, {})
        last, _ = _series_sums(per, start, end)
        if last < NIGHT_MIN_COUNT:
            continue
        past = []
        for i in range(1, 15):
            s, e = _night_window(today - timedelta(days=i))
            cnt, _nx = _series_sums(per, s, e)
            # その日に活動があった端末の夜だけをサンプルにする
            day_total, _ = _series_sums(per, s, s + DAY)
            if day_total > 0:
                past.append(cnt)
        if len(past) < NIGHT_MIN_NIGHTS:
            continue
        # 実測では端末の夜間件数は「ほぼゼロか数百件」の二峰性で、中央値は
        # 基準にならない（NTP リトライやゲームのDLがある夜は平常運転）。
        # 「その端末にとって前例のない夜か」を過去最大との比較で判定する。
        past_max = max(past)
        if last < max(NIGHT_FACTOR * past_max, NIGHT_MIN_COUNT):
            continue
        akey = today.strftime("%Y-%m-%d")
        if already_alerted(conn, ident, "NIGHT", akey, now, days=1):
            continue
        findings.append((ident, "NIGHT", [akey],
                         "■ 夜間通信 %s: 0–5時 %d件 (過去の最大 %d件)"
                         % (identity_label(conn, ident), last, past_max)))
    return findings


# ---------------------------------------------------------------- activeban 橋渡し
# dns_watch は読み取り専用の検知器のまま、危険シグナルだけを activeban に
# report する（append-only の一方向）。執行と検証は activeban 側の仕事で、
# ここでは「定量的な根拠（recent）と普段の様子（baseline）」を同梱する。
# NEW_PAIR / NEW_CLIENT は発見シグナルなので対象にしない。

CANARY_DOMAIN = "canary.activeban.invalid"


def _device_for_identity(conn, identity):
    """identity から activeban の device {mac, ip, name} を組み立てる。"""
    if identity.startswith("mac:"):
        mac = identity[4:].upper()
        row = conn.execute(
            "SELECT ip FROM ip_mac WHERE mac = ? ORDER BY last_seen DESC LIMIT 1",
            (mac,),
        ).fetchone()
        return {"mac": mac, "ip": row[0] if row else None,
                "name": DEVICE_NAMES.get(mac)}
    return {"mac": None, "ip": identity,
            "name": DEVICE_NAMES.get(identity.upper())}


def _baseline_summary(conn, identity, now):
    """端末の普段の様子を state から作る（直近30日）。

    top_domains は「7日以上前から知っている宛先」を普段の集合の近似として
    recent_count 順に最大10件。量と NX 率は hourly の同一性軸集計から。
    """
    series = _id_hourly_series(conn).get(identity, {})
    days = {}
    for hour, (count, nx) in series.items():
        if hour >= now - DAY:
            continue  # 直近24hは「普段」ではない（イベント側の数字なので外す）
        a = days.setdefault(hour // DAY, [0, 0])
        a[0] += count
        a[1] += nx
    per_day = sorted(v[0] for v in days.values())
    median = per_day[len(per_day) // 2] if per_day else 0
    total = sum(v[0] for v in days.values())
    nx_total = sum(v[1] for v in days.values())
    top = [r[0] for r in conn.execute(
        "SELECT domain FROM id_pairs WHERE identity = ? AND first_seen <= ? "
        "ORDER BY recent_count DESC LIMIT 10",
        (identity, now - 7 * DAY)).fetchall()]
    row = conn.execute(
        "SELECT first_seen FROM id_clients WHERE identity = ?",
        (identity,)).fetchone()
    return {
        "period_days": 30,
        "queries_per_day_median": median,
        "top_domains": top,
        "nx_rate": round(nx_total / total, 4) if total else 0.0,
        "first_seen": row[0] if row else None,
    }


def _recent_nx(conn, identity, now):
    """NX_SPIKE 用の recent（直近24h の定量値と新規宛先）。"""
    series = _id_hourly_series(conn).get(identity, {})
    c1, n1 = _series_sums(series, now - DAY, now)
    c0, n0 = _series_sums(series, now - 14 * DAY, now - DAY)
    new_peers = [r[0] for r in conn.execute(
        "SELECT domain FROM id_pairs WHERE identity = ? AND first_seen >= ? "
        "ORDER BY recent_count DESC LIMIT 10",
        (identity, now - DAY)).fetchall()]
    return {
        "window_seconds": DAY,
        "counts": {"queries": c1, "nx": n1},
        "nx_ratio": round(n1 / c1, 4) if c1 else 0.0,
        "baseline_nx_ratio": round(n0 / c0, 4) if c0 else 0.0,
        "new_peers": new_peers,
    }


def build_activeban_event(conn, identity, kind, now):
    """検知結果を activeban の report イベント（JSON dict）に変換する。"""
    device = _device_for_identity(conn, identity)
    baseline = _baseline_summary(conn, identity, now)
    if kind == "NX_SPIKE":
        recent = _recent_nx(conn, identity, now)
        reason = ("NXDOMAIN spike: %d NX of %d queries in 24h (%.0f%%, "
                  "baseline %.0f%%)"
                  % (recent["counts"]["nx"], recent["counts"]["queries"],
                     recent["nx_ratio"] * 100,
                     recent["baseline_nx_ratio"] * 100))
        return {"device": device, "trigger": "behavior", "reason": reason,
                "ttl": CONFIG["activeban"]["ttl_seconds"],
                "evidence": {"recent": recent, "baseline": baseline}}
    return None


def check_canary(conn, now):
    """カナリアドメインへの問い合わせを拾う（直近1時間、10分間は再送しない）。"""
    out = []
    rows = conn.execute(
        "SELECT identity, domain, recent_count FROM id_pairs "
        "WHERE (domain = ? OR domain LIKE ?) AND last_seen >= ?",
        (CANARY_DOMAIN, "%." + CANARY_DOMAIN, now - HOUR)).fetchall()
    for ident, domain, count in rows:
        if already_alerted(conn, ident, "CANARY", domain, now,
                            days=10.0 / 1440):
            continue
        out.append((ident, domain, count))
    return out


def build_canary_event(conn, identity, domain, count):
    test_id = ""
    if domain != CANARY_DOMAIN:
        test_id = domain[: -len(CANARY_DOMAIN)].rstrip(".").split(".")[0]
    return {"device": _device_for_identity(conn, identity),
            "trigger": "canary", "reason": "canary test probe",
            "ttl": CONFIG["activeban"]["canary_ttl_seconds"],
            "evidence": {"canary_domain": domain, "test_id": test_id,
                         "recent": {"window_seconds": HOUR,
                                    "counts": {"queries": count}}}}


def send_activeban(event):
    """イベントを1つ activeban に送る。戻り値は応答 JSON（dict）。

    既定は SSH forced-command（activeban 側の受け口が stdin の JSON を
    そのまま report する）。config の command があればそちらを使う。
    失敗は例外にするか応答の ok で判定できるよう、そのまま返す。
    """
    cfg = CONFIG["activeban"]
    data = json.dumps(event, ensure_ascii=False)
    if cfg.get("command"):
        cmd = list(cfg["command"])
    else:
        cmd = ["ssh", "-T", "-o", "BatchMode=yes",
               "-o", "StrictHostKeyChecking=yes"]
        if cfg.get("ssh_key"):
            cmd += ["-i", os.path.expanduser(cfg["ssh_key"])]
        cmd.append(cfg["ssh_host"])
    r = subprocess.run(cmd, input=data, capture_output=True, text=True,
                       timeout=30)
    if r.returncode != 0:
        raise RuntimeError("activeban send failed (rc=%d): %s"
                           % (r.returncode, r.stderr.strip()[:200]))
    return json.loads(r.stdout)


def bridge_to_activeban(conn, findings, now):
    """危険シグナルとカナリアを activeban に送る（best-effort）。

    Talk 通知が本線なので、橋渡しの失敗で検知の記録を巻き戻さない。
    失敗は標準エラーに残す（activeban 側にもスプールはあるが、届いて
    いないイベントは向こうでは存在しないため、ここで痕跡を残す）。
    """
    cfg = CONFIG["activeban"]
    if not cfg["enabled"]:
        return
    for identity, kind, _akeys, _text in findings:
        if kind not in cfg["report_kinds"]:
            continue
        event = build_activeban_event(conn, identity, kind, now)
        if event is None:
            continue
        try:
            res = send_activeban(event)
            print("activeban report (%s, %s): %s"
                  % (identity, kind, json.dumps(res, ensure_ascii=False)),
                  file=sys.stderr)
        except Exception as e:
            print("activeban report failed (%s, %s): %s" % (identity, kind, e),
                  file=sys.stderr)
    if cfg["canary"]:
        for identity, domain, count in check_canary(conn, now):
            try:
                res = send_activeban(build_canary_event(
                    conn, identity, domain, count))
                print("activeban canary (%s, %s): %s"
                      % (identity, domain,
                         json.dumps(res, ensure_ascii=False)),
                      file=sys.stderr)
                record_alert(conn, identity, "CANARY", domain, now)
            except Exception as e:
                print("activeban canary failed (%s, %s): %s"
                      % (identity, domain, e), file=sys.stderr)


# ---------------------------------------------------------------- 通知
NEXTCLOUD_CONFIG_PATH = os.environ.get(
    "DNS_WATCH_NEXTCLOUD_CONFIG",
    os.path.expanduser("~/.config/lanlookout/nextcloud.json"),
)


def _nextcloud_config():
    """Nextcloud 共通設定を読む（他の監視ツールと共有できるファイル）。

    戻り値: (nextcloud_url, talk_token, username, app_password)
    読めなければ全て空文字。
    """
    try:
        with open(NEXTCLOUD_CONFIG_PATH, encoding="utf-8") as f:
            cfg = json.load(f)
        return (
            cfg["nextcloud_url"],
            cfg["talk_token"],
            cfg.get("username", ""),
            cfg.get("app_password", ""),
        )
    except Exception:
        return "", "", "", ""


def post_talk(message):
    """Nextcloud Talk に投稿する。共通設定が読めなければ標準出力に出して成功扱い。

    timeout は 45s。
    """
    base, token, user, password = _nextcloud_config()
    if not base or not token:
        print(message)
        return
    url = base.rstrip("/") + "/ocs/v2.php/apps/spreed/api/v1/chat/" + token
    body = json.dumps({"message": message}).encode("utf-8")
    req = urllib.request.Request(url, data=body, method="POST")
    req.add_header("Content-Type", "application/json")
    req.add_header("OCS-APIRequest", "true")
    req.add_header("Accept", "application/json")
    if user:
        token = base64.b64encode(("%s:%s" % (user, password)).encode("utf-8"))
        req.add_header("Authorization", "Basic " + token.decode("ascii"))
    with urllib.request.urlopen(req, timeout=45) as resp:
        if resp.status >= 300:
            raise RuntimeError("Talk POST failed: HTTP %d" % resp.status)


# ---------------------------------------------------------------- main
def _open_state():
    """state DB を開き、スキーマと clients の列移行まで済ませて返す。"""
    state_path = CONFIG["state_path"]
    state_dir = os.path.dirname(state_path)
    if state_dir:
        os.makedirs(state_dir, exist_ok=True)
        try:
            os.chmod(state_dir, 0o700)  # DNS の記録は家庭内の機微情報として扱う
        except OSError:
            pass
    conn = sqlite3.connect(state_path)
    conn.executescript(SCHEMA)
    # clients への name/mac 追加（既存 state の移行）
    _cols = {r[1] for r in conn.execute("PRAGMA table_info(clients)")}
    if "name" not in _cols:
        conn.execute("ALTER TABLE clients ADD COLUMN name TEXT")
    if "mac" not in _cols:
        conn.execute("ALTER TABLE clients ADD COLUMN mac TEXT")
    # ip_mac_history の種まき（既存 state の移行）: 履歴が無い IP は
    # 現在の ip_mac を「first_seen から継続中」の区間として登録する
    conn.execute(
        """
        INSERT OR IGNORE INTO ip_mac_history (ip, mac, valid_from, valid_to)
        SELECT ip, mac, first_seen, NULL FROM ip_mac
        WHERE mac IS NOT NULL AND mac != ''
          AND ip NOT IN (SELECT ip FROM ip_mac_history)
        """
    )
    conn.commit()
    return conn


def run(now, bootstrap=False, dry_run=False):
    global HONOR_ALERTS
    # dry-run はプレビュー専用: alerts の抑制を見ず、今マッチする所見を
    # 全部出す（記録もしない）。本番実行の検証が抑制に邪魔されないため。
    HONOR_ALERTS = not dry_run
    span = BOOTSTRAP_DAYS * DAY if bootstrap else RECENT_HOURS * HOUR
    start, end = now - span, now

    # 収集を先に全部済ませ、ノード間で合算する。1台でも失敗したら
    # state を進めずに異常終了。
    combined = collect_all(start, end)
    DEVICE_NAMES.clear()
    DEVICE_NAMES.update(_load_device_names())
    learned = learn_ip_mac(CONFIG["arp_sweep"]) if CONFIG["arp_learn"] else {}

    conn = _open_state()
    try:
        conn.execute("BEGIN")
        if bootstrap:
            # 種まきは常に更地から（再 bootstrap で壊れたベースラインを作り直せる）
            for table in ("pairs", "hourly", "clients", "alerts",
                          "id_pairs", "id_clients"):
                conn.execute("DELETE FROM %s" % table)
        merge(conn, combined, learned, now)

        if bootstrap:
            n_pairs = conn.execute("SELECT COUNT(*) FROM pairs").fetchone()[0]
            n_clients = conn.execute("SELECT COUNT(*) FROM clients").fetchone()[0]
            conn.commit()
            print("bootstrap done: pairs=%d clients=%d" % (n_pairs, n_clients))
            return 0

        findings = []
        findings += check_new_clients(conn, now)
        new_ids = {f[0] for f in findings if f[1] == "NEW_CLIENT"}
        findings += check_new_pairs(
            conn, now, skip_identities=new_ids | known_released_identities(conn, now)
        )
        findings += check_nx_spike(conn, now)
        findings += check_night(conn, now)
        # リゾルバ自身 (127.0.0.1 等) は「クライアント」ではない。FTL が
        # 端末のホスト名を引く PTR 問い合わせ等がここに出るため丸ごと外す。
        findings = [f for f in findings if f[0] not in SELF_IPS]
        if CONFIG["ignore_clients"]:
            findings = [
                f for f in findings
                if f[1] == "NEW_CLIENT"
                or not _identity_matches_ips(conn, f[0], CONFIG["ignore_clients"])
            ]

        if not findings:
            # 所見が無くてもカナリアだけは橋渡しする（動作確認プローブ）
            bridge_to_activeban(conn, [], now)
            conn.commit()
            return 0

        message = "[dns_watch] DNSベースライン逸脱を検知\n" + "\n".join(
            f[3] for f in findings
        )
        if dry_run:
            print(message)
            conn.commit()  # state は進めるが alerts は記録しない（調整用）
            return 0

        post_talk(message)  # 失敗したら例外 → rollback して exit 2
        # 危険シグナルだけ activeban へ（best-effort、失敗しても記録は進める）
        bridge_to_activeban(conn, findings, now)
        for client, kind, akeys, _text in findings:
            for akey in akeys:
                record_alert(conn, client, kind, akey, now)
        conn.commit()
        return 0
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def cmd_labels(now, only_ip=None):
    """名前解決だけを確認する（検知 state は進めない）。

    ARP 学習と ip_mac / clients.mac の同期だけを行ってラベルを表示する。
    所見の有無に左右されず、いつでも同定状況を点検できる。
    """
    DEVICE_NAMES.clear()
    DEVICE_NAMES.update(_load_device_names())
    learned = learn_ip_mac(CONFIG["arp_sweep"]) if CONFIG["arp_learn"] else {}
    conn = _open_state()
    for ip, mac in learned.items():
        _record_ip_mac(conn, ip, mac, now)
    conn.execute(
        """
        UPDATE clients SET mac = (
          SELECT mac FROM ip_mac WHERE ip_mac.ip = clients.client
        ) WHERE client IN (SELECT ip FROM ip_mac)
        """
    )
    conn.execute("UPDATE clients SET mac = NULL WHERE mac LIKE 'ip-%'")
    conn.commit()
    if only_ip:
        print(client_label(conn, only_ip))
    else:
        rows = conn.execute("SELECT client FROM clients ORDER BY client").fetchall()
        for (ip,) in rows:
            print(client_label(conn, ip))
    conn.close()
    return 0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--bootstrap", action="store_true")
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--label", nargs="?", const="", default=None, metavar="IP")
    args = ap.parse_args()
    now = int(datetime.now().timestamp())
    try:
        if args.label is not None:
            return cmd_labels(now, args.label or None)
        return run(now, bootstrap=args.bootstrap, dry_run=args.dry_run)
    except Exception as e:  # 収集・通知の失敗は state を進めず exit 2
        print("dns_watch: %s" % e, file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
