#!/usr/bin/env python3
"""dns_audit.py — dns_watch ベースラインの一回きり静的監査（読み取り専用）。

dns_watch は「端末ごとの平常からの逸脱」を見る仕組みなので、ベースライン
確立時点で既に乗っ取られて安定している端末は原理的に検知できない。
このスクリプトは蓄積されたベースライン自体を監査する一回きりの道具:

  1. dns_watch と同じ収集経路（ssh + pihole_collect.py）で、FTL DB の
     全履歴（--days 指定時はその日数分）の (端末 x ドメイン) ペアを取る。
  2. 脅威インテル（ドメインリスト）と照合する（完全一致＋親ドメイン遡り）。
  3. 構造的な特徴でスクリーニングする:
       - singleton_machine: 機器らしい端末だけが少数回引く、家で単独の宛先
       - nx_heavy:          NXDOMAIN が偏っているペア（DGA の残骸・死んだ C2）
       - dga_like:          ラベルのエントロピーが高い（DGA 臭）
       - deep_name:         ラベル数が多い / 名前が長い（トンネリング臭）
       - long_token:        長い hex トークンのラベル（弱いシグナルとして分離）
  4. 結果を Markdown レポートに書き、要約を標準出力に出す。

state DB には書かない。通知もしない。判定は決定的処理のみで、最終判断は人。
インテルリストは --intel で複数指定可。無指定なら ./intel/*.txt を全部読む。
形式は plain（1行1ドメイン）/ hosts（0.0.0.0 domain）/ adblock（||domain^）
/ URL 行のいずれでもよい。

メモリ設計（重要）: 監視ホストは低メモリ（1GB RAM 級）を想定する。全履歴を一括で抱える作りは
成立しない（実際に凍らせた）。v2 は:
  - ノードごとに収集し、ペア集計へ取り込んだら生レスポンスを捨てる
  - dns_watch.collect_all は使わない（hourly の合算は監査に不要）
  - 保持するのはペア集計・ドメイン統計・所見だけ
それでもインテル全件（HaGeZi TIF 約230万件）とペア集計で数百MB は使う。
大きなインテルリストで実行する前には、監視ホストのメモリに余裕を持たせること。

使い方（監視ホスト上、dns_watch.py と同じディレクトリで）:
  python3 dns_audit.py                      # 全履歴、./intel/*.txt を使用
  python3 dns_audit.py --days 30 --intel tif.txt --intel urlhaus.txt
"""

import argparse
import math
import os
import sqlite3
import sys
import time
from collections import defaultdict
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import dns_watch  # 収集・設定・ラベル付けを再利用する

JST = timezone(timedelta(hours=9))
DAY = 86400

# ---- スクリーニングの閾値（調整はここ） ----
# DGA 判定は「長さに対するエントロピーの比」で見る。長さ L の文字列の
# エントロピー上限は log2(L) なので、絶対値だけでは短いラベルを判定できない
# （例: 12 文字オールユニークでも H=3.58 が天井）。ランダム文字列は比が
# 1.0 に張り付き、英単語的なラベルは繰り返しで比が下がる。
DGA_MIN_LEN = 12          # この長さ以上のラベルを DGA 判定の対象にする
DGA_MIN_H = 3.3           # エントロピーの絶対下限
DGA_MIN_SCORE = 0.92      # H / log2(len) の下限
DGA_LONG_LEN = 20         # 長いラベルは少し緩める
DGA_LONG_H = 3.6
DGA_LONG_SCORE = 0.88
TOKEN_MIN_LEN = 24        # hex トークンとみなす最小長
DEEP_LABELS = 6           # ラベル数がこれ以上なら deep_name
DEEP_LENGTH = 80          # 全長がこれ以上でも deep_name
NX_HEAVY_MIN = 30         # nx_heavy とみなす最低クエリ数
NX_HEAVY_RATIO = 0.5      # nx_heavy とみなす最低 NX 率
SINGLETON_MAX_COUNT = 10  # singleton_machine とみなす最大クエリ数
SMALL_DEVICE_MAX_PAIRS = 50  # この宛先ペア数以下の端末は全宛先を列挙する

# 登録可能ドメインのラベルを推定するための、よくある2段パブリックサフィックス
_TWO_LEVEL_SUFFIXES = {
    "co.jp", "ne.jp", "or.jp", "ac.jp", "go.jp", "ed.jp", "gr.jp", "lg.jp",
    "co.uk", "org.uk", "ac.uk", "com.au", "net.au", "org.au", "co.nz",
    "com.br", "com.cn", "com.tw", "co.kr", "com.hk", "com.sg", "co.in",
    "com.mx", "com.ar", "co.za",
}


def _entropy(s):
    if not s:
        return 0.0
    counts = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _registrable_label(domain):
    labels = domain.split(".")
    if len(labels) < 2:
        return labels[0] if labels else ""
    if ".".join(labels[-2:]) in _TWO_LEVEL_SUFFIXES and len(labels) >= 3:
        return labels[-3]
    return labels[-2]


# ---------------------------------------------------------------- インテル
def _parse_intel_line(line):
    s = line.strip().lower()
    if not s or s[0] in "#!;":
        return None
    if s.startswith("||"):  # adblock 形式: ||domain^ / ||domain^$options
        s = s[2:].split("^")[0].split("$")[0].split("/")[0]
    elif "://" in s:  # URL 行: ホスト部だけ取る
        s = s.split("://", 1)[1].split("/")[0].split(":")[0]
    else:
        parts = s.split()
        if len(parts) >= 2:  # hosts 形式: 0.0.0.0 domain / 127.0.0.1 domain
            s = parts[1]
        else:
            s = parts[0]
    s = s.strip().strip(".")
    if not s or "." not in s or " " in s or "/" in s or "*" in s:
        return None
    return s


def load_intel(paths):
    domains = set()
    per_file = {}
    for path in paths:
        n0 = len(domains)
        with open(path, encoding="utf-8", errors="replace") as f:
            for line in f:
                d = _parse_intel_line(line)
                if d:
                    domains.add(d)
        per_file[path] = len(domains) - n0
    return domains, per_file


def intel_hit(domain, intel):
    """domain 自身と親ドメインを遡って照合し、一致した登録名を返す。"""
    labels = domain.split(".")
    for i in range(0, len(labels) - 1):
        cand = ".".join(labels[i:])
        if cand in intel:
            return cand
    return None


# ---------------------------------------------------------------- 構造判定
def structural_flags(domain):
    """(kind, detail) のリストを返す。kind はレポートの節名になる。"""
    flags = []
    labels = domain.split(".")
    if len(labels) >= DEEP_LABELS or len(domain) >= DEEP_LENGTH:
        flags.append(("deep_name", "labels=%d len=%d" % (len(labels), len(domain))))

    candidates = set()
    reg = _registrable_label(domain)
    if reg:
        candidates.add(reg)
    for lab in labels[:-1]:  # TLD 以外
        if len(lab) >= DGA_MIN_LEN:
            candidates.add(lab)
    best_dga = None
    token = None
    for lab in candidates:
        if lab.isdigit():
            continue
        if len(lab) >= TOKEN_MIN_LEN and all(c in "0123456789abcdef" for c in lab):
            token = lab
            continue
        e = _entropy(lab)
        score = e / math.log2(len(lab)) if len(lab) > 1 else 0.0
        if (len(lab) >= DGA_MIN_LEN and e >= DGA_MIN_H and score >= DGA_MIN_SCORE) or (
            len(lab) >= DGA_LONG_LEN and e >= DGA_LONG_H and score >= DGA_LONG_SCORE
        ):
            if best_dga is None or e > best_dga[1]:
                best_dga = (lab, e)
    if best_dga:
        flags.append(("dga_like", "%s H=%.2f" % best_dga))
    elif token:
        flags.append(("long_token", token[:24] + "..."))
    return flags


# ---------------------------------------------------------------- 収集
def collect_pairs(start, end):
    """ノードごとに収集し、ペア集計へ逐次取り込んで返す。

    戻り値: (pairs, client_info)
      pairs: {(client, domain): [count, nx, first_ts, last_ts]}
    hourly は監査に不要なので捨てる。生レスポンスは取り込み次第解放する。
    """
    pairs = {}
    info = {}
    for node in dns_watch.CONFIG["nodes"]:
        print("collecting %s ..." % node, flush=True)
        data = dns_watch.collect(node, start, end)
        for ip, entry in (data.get("client_info") or {}).items():
            cur = info.setdefault(ip, {"name": "", "mac": ""})
            if entry.get("name"):
                cur["name"] = entry["name"]
            if entry.get("mac"):
                cur["mac"] = entry["mac"]
        n = 0
        for client, domain, count, nx, first_ts, last_ts in data["pairs"]:
            d = domain.strip().lower().rstrip(".")
            if not d or "." not in d:
                continue
            cur = pairs.get((client, d))
            if cur is None:
                pairs[(client, d)] = [count, nx, first_ts, last_ts]
            else:
                cur[0] += count
                cur[1] += nx
                cur[2] = min(cur[2], first_ts)
                cur[3] = max(cur[3], last_ts)
            n += 1
        print("  %s: %d pairs（累計 %d）" % (node, n, len(pairs)), flush=True)
        del data
    return pairs, info


# ---------------------------------------------------------------- ラベル
def _make_labeler(client_info):
    """dns_watch と同じ 'IP (名前, MAC)' 表記を返す関数を作る。

    state DB は読み取り専用で開く（監査は state を進めない）。
    開けない環境では収集結果の client_info で代替する。
    """
    cache = {}
    conn = None
    try:
        dns_watch.DEVICE_NAMES.update(dns_watch._load_device_names())
        conn = sqlite3.connect(
            "file:%s?mode=ro" % dns_watch.CONFIG["state_path"], uri=True
        )
    except Exception:
        conn = None

    def label(client):
        if client in cache:
            return cache[client]
        text = None
        if conn is not None:
            try:
                text = dns_watch.client_label(conn, client)
            except Exception:
                text = None
        if not text:
            name = (client_info.get(client) or {}).get("name") or ""
            if name == "ip-" + client:
                name = ""
            text = client + (" (%s)" % name if name else "")
        cache[client] = text
        return text

    return label


def _fmt_ts(epoch):
    if not epoch:
        return "-"
    return datetime.fromtimestamp(epoch, JST).strftime("%Y-%m-%d %H:%M")


# ---------------------------------------------------------------- 本体
def run_audit(start, end, intel_paths, out_path, section_max, small_max_pairs=SMALL_DEVICE_MAX_PAIRS):
    pairs, client_info = collect_pairs(start, end)
    if not pairs:
        print("dns_audit: ペアが取れませんでした（FTL DB が空？）")
        return 2

    first_all = min(v[2] for v in pairs.values())
    last_all = max(v[3] for v in pairs.values())
    window_days = max(1.0, (last_all - first_all) / DAY)
    # 機器らしい端末の目安は dns_watch の NEW_PAIR 基準（30日で N ペア）を
    # 監査ウィンドウの日数で比例換算する
    machine_max_pairs = int(
        dns_watch.CONFIG["new_pair_max_client_pairs"] * window_days / 30.0
    )

    intel = set()
    per_file = {}
    if intel_paths:
        print("loading intel ...", flush=True)
        intel, per_file = load_intel(intel_paths)
        print("  intel: %d domains" % len(intel), flush=True)

    label = _make_labeler(client_info)

    # ドメイン統計は set でなく [端末数, 端末数==1 のときの唯一の端末] で持つ
    domain_stat = {}  # domain -> [n_clients, only_client]
    client_pairs = defaultdict(int)
    client_queries = defaultdict(int)
    for (client, domain), v in pairs.items():
        st = domain_stat.get(domain)
        if st is None:
            domain_stat[domain] = [1, client]
        elif st[1] != client:
            st[0] += 1
            st[1] = None
        client_pairs[client] += 1
        client_queries[client] += v[0]
    machine_like = {c for c, n in client_pairs.items() if n <= machine_max_pairs}

    print("screening %d pairs ..." % len(pairs), flush=True)
    intel_hits = []  # (client, domain, matched, count, nx, first, last)
    flagged = defaultdict(list)  # kind -> [(client, domain, count, nx, first, last, detail)]
    rollup = defaultdict(lambda: {"intel": 0, "flags": 0})
    for (client, domain), (count, nx, first_ts, last_ts) in pairs.items():
        hit = intel_hit(domain, intel) if intel else None
        if hit:
            intel_hits.append((client, domain, hit, count, nx, first_ts, last_ts))
            rollup[client]["intel"] += 1
        kinds = structural_flags(domain)
        if nx >= NX_HEAVY_MIN and count > 0 and nx / count >= NX_HEAVY_RATIO:
            kinds.append(("nx_heavy", "nx=%d/%d" % (nx, count)))
        if (
            domain_stat[domain][0] == 1
            and client in machine_like
            and count <= SINGLETON_MAX_COUNT
        ):
            kinds.append(("singleton_machine", "queries=%d" % count))
        for kind, detail in kinds:
            flagged[kind].append(
                (client, domain, count, nx, first_ts, last_ts, detail)
            )
            rollup[client]["flags"] += 1

    intel_hits.sort(key=lambda r: (r[0], r[1]))
    total_queries = sum(client_queries.values())

    # ------------------------------------------------ レポート生成
    L = []
    L.append("# DNS 静的監査レポート")
    L.append("")
    L.append("- 対象期間: %s 〜 %s（%.0f 日）" % (_fmt_ts(first_all), _fmt_ts(last_all), window_days))
    L.append("- 総クエリ数（両ノード合算）: %d" % total_queries)
    L.append("- ペア数: %d / ユニークドメイン数: %d / 端末数: %d" % (len(pairs), len(domain_stat), len(client_pairs)))
    L.append("- 機器らしい端末の目安: 期間中の宛先ペア数 <= %d" % machine_max_pairs)
    if intel_paths:
        L.append("- インテル: %d 件（%s）" % (len(intel), ", ".join("%s: %d" % (os.path.basename(p), n) for p, n in per_file.items())))
    else:
        L.append("- インテル: なし（構造スクリーニングのみ）")
    L.append("")

    L.append("## 脅威インテル一致（%d 件）" % len(intel_hits))
    L.append("")
    if intel_hits:
        for client, domain, hit, count, nx, first_ts, last_ts in intel_hits:
            L.append("- %s -> `%s`（一致: `%s`）%d 回, 初出 %s, 最終 %s" % (label(client), domain, hit, count, _fmt_ts(first_ts), _fmt_ts(last_ts)))
    else:
        L.append("（なし）")
    L.append("")

    L.append("## 端末別ロールアップ（所見のある端末のみ）")
    L.append("")
    ranked = sorted(
        rollup.items(), key=lambda kv: (-kv[1]["intel"], -kv[1]["flags"], kv[0])
    )
    if ranked:
        L.append("| 端末 | ペア数 | クエリ数 | インテル | 構造フラグ |")
        L.append("|---|---|---|---|---|")
        for client, r in ranked:
            L.append("| %s | %d | %d | %d | %d |" % (label(client), client_pairs[client], client_queries[client], r["intel"], r["flags"]))
    else:
        L.append("（所見なし）")
    clean = len(client_pairs) - len(ranked)
    L.append("")
    L.append("所見のない端末: %d 台" % clean)
    L.append("")

    # 小物デバイスの全宛先: 宛先が数十個しかない端末は「ほかのサイト」
    # を含めて全数レビューできる。IoT の静的監査の本命はここ。
    small_clients = sorted(
        (c for c, n in client_pairs.items() if n <= small_max_pairs),
        key=lambda c: (client_pairs[c], c),
    )
    by_client = defaultdict(list)
    for (client, domain), v in pairs.items():
        if client_pairs[client] <= small_max_pairs:
            by_client[client].append((domain, v[0], v[1], v[2], v[3]))
    L.append("## 小物デバイスの全宛先（宛先ペア数 <= %d の端末 %d 台）" % (small_max_pairs, len(small_clients)))
    L.append("")
    for client in small_clients:
        rows = sorted(by_client[client], key=lambda r: -r[1])
        L.append("- **%s**（%d 宛先 / %d クエリ）" % (label(client), client_pairs[client], client_queries[client]))
        for domain, count, nx, first_ts, last_ts in rows:
            L.append("  - `%s` %d 回, 初出 %s, 最終 %s" % (domain, count, _fmt_ts(first_ts), _fmt_ts(last_ts)))
    if not small_clients:
        L.append("（なし）")
    L.append("")

    section_titles = [
        ("singleton_machine", "単独宛先（機器らしい端末だけが引くドメイン、初出の古い順）"),
        ("nx_heavy", "NXDOMAIN 偏重"),
        ("dga_like", "DGA 的ラベル"),
        ("deep_name", "深い / 長い名前"),
        ("long_token", "長い hex トークンのラベル（弱いシグナル）"),
    ]
    sorters = {
        "singleton_machine": lambda r: r[4],            # first_ts 昇順
        "nx_heavy": lambda r: -r[3],                    # nx 降順
        "dga_like": lambda r: -r[2],                    # count 降順
        "deep_name": lambda r: -len(r[1]),
        "long_token": lambda r: -r[2],
    }
    for kind, title in section_titles:
        rows = sorted(flagged.get(kind, []), key=sorters[kind])
        L.append("## %s（%d 件）" % (title, len(rows)))
        L.append("")
        for client, domain, count, nx, first_ts, last_ts, detail in rows[:section_max]:
            L.append("- %s -> `%s` %d 回（%s）, 初出 %s" % (label(client), domain, count, detail, _fmt_ts(first_ts)))
        if len(rows) > section_max:
            L.append("- … 他 %d 件（--section-max で拡大可）" % (len(rows) - section_max))
        if not rows:
            L.append("（なし）")
        L.append("")

    L.append("## 読み方と限界")
    L.append("")
    L.append("- インテル一致は「既知の悪性リストに載る宛先を引いた」事実のみを示す。リストの鮮度と網羅性に依存し、一致ゼロは無感染の証明ではない。")
    L.append("- 構造フラグはレビュー候補の抽出であり、断定ではない。正規のテレメトリや CDN も拾い得る。")
    L.append("- DNS に現れない通信（IP 直アクセス、独自 DoH）はこの監査でも見えない。")
    L.append("- ルーター配下の集約など、宛先ペア数が目安を超える端末は singleton 判定の対象外。")
    L.append("")

    report = "\n".join(L)
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(report)

    # ------------------------------------------------ 標準出力の要約
    print("== DNS 静的監査 ==")
    print("期間: %s 〜 %s（%.0f 日） / ペア %d / ドメイン %d / 端末 %d / クエリ %d" % (_fmt_ts(first_all), _fmt_ts(last_all), window_days, len(pairs), len(domain_stat), len(client_pairs), total_queries))
    print("インテル一致: %d 件" % len(intel_hits))
    for client, domain, hit, count, nx, first_ts, last_ts in intel_hits[:60]:
        print("  [intel] %s -> %s （一致: %s）%d 回, 初出 %s" % (label(client), domain, hit, count, _fmt_ts(first_ts)))
    if len(intel_hits) > 60:
        print("  … 他 %d 件（レポート参照）" % (len(intel_hits) - 60))
    for kind, title in section_titles:
        print("%s: %d 件" % (kind, len(flagged.get(kind, []))))
    print("小物デバイス（宛先 <= %d）: %d 台（全宛先をレポートに記載）" % (small_max_pairs, len(small_clients)))
    print("所見のある端末: %d 台 / なし: %d 台" % (len(ranked), clean))
    for client, r in ranked[:10]:
        print("  %s: インテル %d / フラグ %d" % (label(client), r["intel"], r["flags"]))
    print("レポート: %s" % out_path)
    return 0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--days", type=int, default=0, help="遡る日数（0 = FTL DB の全履歴）")
    ap.add_argument("--intel", action="append", default=[], help="インテルリストのパス（複数可）")
    ap.add_argument("--out", default="", help="レポートの出力先")
    ap.add_argument("--section-max", type=int, default=150, help="節ごとの最大表示件数")
    ap.add_argument("--small-max-pairs", type=int, default=SMALL_DEVICE_MAX_PAIRS, help="全宛先を列挙する端末の宛先ペア数上限")
    args = ap.parse_args()

    intel_paths = list(args.intel)
    if not intel_paths:
        intel_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "intel")
        if os.path.isdir(intel_dir):
            intel_paths = sorted(
                os.path.join(intel_dir, n)
                for n in os.listdir(intel_dir)
                if n.endswith(".txt")
            )
    if not intel_paths:
        print("dns_audit: インテルリストが無いため構造スクリーニングのみ行います", file=sys.stderr)

    now = int(time.time())
    start = 0 if args.days <= 0 else now - args.days * DAY
    out_path = args.out or os.path.abspath(
        "dns-audit-%s.md" % datetime.fromtimestamp(now, JST).strftime("%Y%m%d-%H%M")
    )
    return run_audit(start, now, intel_paths, out_path, args.section_max, args.small_max_pairs)


if __name__ == "__main__":
    sys.exit(main())
