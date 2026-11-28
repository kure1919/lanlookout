#!/usr/bin/env python3
"""dns_watch.py — Pi-hole 2台の DNS クエリを監視ホストに集約し、端末別ベースライン
からの逸脱を検知して Nextcloud Talk に通知する。読み取り専用。

運用型:
  - systemd timer から定期実行
  - 検知の記録と橋渡しイベントは同一トランザクションで確定させ、
    配信（Talk / activeban）は commit 後に互いに独立して行う
  - Talk が不達ならメッセージを talk_spool.jsonl に積み、次回実行で
    先に流す（at-least-once）。不達があった実行は exit 2 で知らせる
  - 橋渡しが不達ならイベントは bridge_outbox に残り、次回実行で再試行する
  - 重複通知は alerts テーブルの記録で抑止する

検知項目:
  NEW_PAIR   端末が初めて引いたドメイン（24h 以内に first_seen、24h で 2 回以上）
  NEW_CLIENT ベースラインに無かった端末の出現
  NX_SPIKE   端末の NXDOMAIN 率・件数が平常時から跳ねた（DGA / 設定ミス兆候）
  NIGHT      0–5 時の通信量がその端末の平常夜間から跳ねた
  INTEL      直近24hの宛先が脅威インテルリストに一致（任意・intel 設定）
  NEW_PAIR_BURST 24h の新規宛先の件数そのものが跳ねた（無差別な探索の型）
  TREND      10日バケットで見た通信量・新規宛先数が増え続ける（徐汚染の型。
             機器らしい端末のみ・通知のみ）

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
       intel            脅威インテル突き合わせ（任意・既定は無効）。
                        enabled / path（1行1ドメインのリスト）/ name。
                        リストの取得・更新は intel_fetch.py が担う。
       new_pair_burst_threshold
                        NEW_PAIR_BURST とみなす 24h 新規宛先数。既定 30。
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
NX_DELTA_MIN = 0.30          # 率の差分（pt）でも発火させる下限。
                             # 平常率が高い端末では 3 倍条件が率 100% を
                             # 超えて永遠に発火しないため、差分を併用する
NIGHT_MIN_COUNT = 100        # 夜間急増とみなす 0–5 時の最低件数
NIGHT_FACTOR = 1.5           # 過去夜間の最大値の何倍で「前例のない夜」とするか
NIGHT_MIN_NIGHTS = 5         # 判定に必要な過去夜間のサンプル数
ALERT_SUPPRESS_DAYS = 7      # 同一所見の再通知を抑える日数
# TREND（緩やかな増加）: 短窓比較では平常に取り込まれる坂を見る。
# 対象は NEW_PAIR と同じ「機器らしい端末」だけ（人の端末の増加は正常）。
# 通知のみで、activeban への報告対象にはしない。
TREND_BUCKET_DAYS = 10       # 傾きを見るバケット幅
TREND_MIN_AGE_DAYS = 40      # これより若い端末は判定しない（新規は除外）
TREND_VOL_BUCKETS = 3        # 通信量: 直近 30 日を 3 バケットで見る
TREND_VOL_STEP = 1.25        # バケット毎に最低この倍率で増えていること
TREND_VOL_TOTAL = 2.0        # 最初→最後で最低この倍率
TREND_VOL_MIN = 50           # 最終バケットの日次中央値の絶対下限/日
TREND_DST_BUCKETS = 4        # 宛先種類: 直近 40 日を 4 バケットで見る
TREND_DST_MIN_LAST = 10      # 最終バケットの新規宛先数の下限
TREND_DST_TOTAL = 3.0        # 最初→最後で最低この倍率
TREND_SUPPRESS_DAYS = 30     # 同一所見の再通知を抑える日数
# 「機器らしい」適格は、異常発生前の姿で判定する。直近の窓の宛先数を
# そのまま数えると、暴れた端末自身が宛先数を押し上げて上限を超え、
# 検知対象から卒業してしまう（自己除外）。そこで first_seen が
# ESTABLISHED_DAYS より古い＝確立済みの宛先だけを数える。
ESTABLISHED_DAYS = 7
INTEL_STALE_HOURS = 48       # インテルリストがこの時間更新されなければ警告
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
        # 脅威インテル突き合わせ（INTEL 検知）。リストは1行1ドメインの
        # テキストで、intel_fetch.py が別途更新する。広告系リストでは
        # なくマルウェア/C2・フィッシング専用の高精度フィードを使う
        # こと（触っただけでバンに繋がるため）。
        "intel": {
            "enabled": bool((cfg.get("intel") or {}).get("enabled", False)),
            "path": os.path.expanduser(
                (cfg.get("intel") or {}).get(
                    "path", "~/.config/lanlookout/intel_domains.txt")),
            "name": str((cfg.get("intel") or {}).get("name", "intel feed")),
        },
        # 新規宛先バースト（NEW_PAIR_BURST）とみなす 24h 新規宛先数。
        "new_pair_burst_threshold": int(
            cfg.get("new_pair_burst_threshold", 30)),
        # インテルリストの取得元（intel_fetch.py が使う）。既定は
        # キー不要で引けるマルウェア/フィッシング系フィード2件。
        # abuse.ch 本家は 2026-10 から Auth-Key 必須になったため、
        # URLhaus 由来はこちら（domains 抽出済みのミラー）を使う。
        "intel_sources": list(cfg.get("intel_sources", [
            "https://malware-filter.gitlab.io/malware-filter/"
            "urlhaus-filter-domains-online.txt",
            "https://openphish.com/feed.txt",
        ])),
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
        # 直近 new_pair_window_days 日に観測された宛先ペア数がこれを超える
        # クライアントは人間の端末とみなして除外する（人間は毎日100件以上
        # の新規ドメインを踏むので検知にならない）。生涯累計で数えると、
        # 宛先が少しずつ増える IoT がいずれ永久に対象外になるため窓で数える。
        "new_pair_max_client_pairs": int(cfg.get("new_pair_max_client_pairs", 400)),
        "new_pair_window_days": int(cfg.get("new_pair_window_days", 90)),
        # ベースラインの保持期間。これより古い pairs / id_pairs と hourly
        # は実行時に捨てる（ベースラインは最近の姿であって生涯記録ではない）。
        "retention_days": int(cfg.get("retention_days", 180)),
        "hourly_retention_days": int(cfg.get("hourly_retention_days", 40)),
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
CREATE TABLE IF NOT EXISTS bridge_outbox (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  queued_at INTEGER, identity TEXT, kind TEXT, event TEXT,
  attempts INTEGER DEFAULT 0, last_error TEXT
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
        for w in data.get("warnings") or []:
            # 収集側の警告（例: NX が測れないスキーマ）は握り潰さず、
            # ジャーナルに残す。「静か」と「測れていない」を区別するため。
            print("collector warning (%s): %s" % (node, w), file=sys.stderr)
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
    「機器らしい」判定の宛先数は、直近 new_pair_window_days 日の窓の
    うち first_seen が ESTABLISHED_DAYS より古い＝確立済みの宛先だけを
    数える（生涯累計だと、宛先が少しずつ増える IoT が永久に対象外に
    なる。逆に窓の全数を数えると、暴れた端末が自分の宛先数で上限を
    超えて検知対象から卒業してしまう＝自己除外）。
    """
    findings = []  # (identity, kind, akey, text)
    rows = conn.execute(
        """
        SELECT identity, domain, recent_count FROM id_pairs
        WHERE first_seen >= ? AND recent_count >= ?
          AND domain LIKE '%.%'
          AND (SELECT COUNT(*) FROM id_pairs q
               WHERE q.identity = id_pairs.identity AND q.last_seen >= ?
                 AND q.first_seen < ?) <= ?
        ORDER BY identity, recent_count DESC
        """,
        (now - DAY, NEW_PAIR_MIN_COUNT,
         now - CONFIG["new_pair_window_days"] * DAY,
         now - ESTABLISHED_DAYS * DAY,
         CONFIG["new_pair_max_client_pairs"]),
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
        if n0 >= 10:
            # 倍率か差分のどちらかで発火。倍率だけだと平常率が約 1/3
            # 以上の端末（死んだベンダークラウドを叩き続ける等）は
            # 3 倍が 100% を超えて永遠に発火しない。
            factor_hit = ratio1 >= NX_BASELINE_FACTOR * ratio0
            delta_hit = (ratio1 - ratio0) >= NX_DELTA_MIN
            if not (factor_hit or delta_hit):
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

# ---------------------------------------------------------------- インテル

_INTEL_CACHE = {"path": None, "mtime": None, "domains": frozenset()}


def load_intel_domains():
    """インテルリスト（1行1ドメイン、# 始まりはコメント）を読む。

    読めない・無い場合は空集合（= INTEL 検知は黙って無効。リストの
    取得失敗で検知全体を落とさない）。mtime が変わった時だけ読み直す。
    """
    path = CONFIG["intel"]["path"]
    try:
        mtime = os.path.getmtime(path)
    except OSError:
        return frozenset()
    if _INTEL_CACHE["path"] == path and _INTEL_CACHE["mtime"] == mtime:
        return _INTEL_CACHE["domains"]
    domains = set()
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            for line in f:
                d = line.strip().lower().rstrip(".")
                if d and not d.startswith("#"):
                    domains.add(d)
    except OSError:
        return frozenset()
    _INTEL_CACHE.update(path=path, mtime=mtime, domains=frozenset(domains))
    return _INTEL_CACHE["domains"]


def intel_match(domain, listed):
    """domain がリスト記載ドメイン自身かそのサブドメインなら記載側を返す。

    巻き上げるのは「記載ドメインの配下」方向だけ。記載されたサブ
    ドメインから親や兄弟へは広げない（共有ホスティング等の巻き添え
    回避）。
    """
    d = domain.lower().rstrip(".")
    while d:
        if d in listed:
            return d
        if "." not in d:
            return None
        d = d.split(".", 1)[1]
    return None


def check_intel(conn, now):
    """脅威インテル一致: 直近24hに触った宛先を静的リストと突き合わせる。

    first_seen を問わないのが要点。ベースラインに毒が入って「普段の
    宛先」化した C2 はベースライン系の検知では原理的に拾えないが、
    静的リストなら拾える。再通知は (同一性, ドメイン) で1日抑制。
    """
    findings = []
    if not CONFIG["intel"]["enabled"]:
        return findings
    listed = load_intel_domains()
    if not listed:
        return findings
    rows = conn.execute(
        "SELECT identity, domain, recent_count FROM id_pairs "
        "WHERE last_seen >= ? ORDER BY identity, recent_count DESC",
        (now - DAY,)).fetchall()
    by_id = {}
    for ident, domain, count in rows:
        entry = intel_match(domain, listed)
        if entry:
            by_id.setdefault(ident, []).append((domain, count))
    for ident, items in sorted(by_id.items()):
        fresh = [(d, c) for d, c in items
                 if not already_alerted(conn, ident, "INTEL", d, now, days=1)]
        if not fresh:
            continue
        shown = fresh[:NEW_PAIR_MAX_PER_CLIENT]
        text = "、".join("%s (%d回)" % (_defang(d), c) for d, c in shown)
        if len(fresh) > len(shown):
            text += " ほか%d件" % (len(fresh) - len(shown))
        findings.append((ident, "INTEL", [d for d, _ in fresh],
                         "■ 脅威インテル一致 %s: %s [%s]"
                         % (identity_label(conn, ident), text,
                            CONFIG["intel"]["name"])))
    return findings


def check_intel_health(conn, now):
    """インテルリスト自体の健全性。監視の無言の死を防ぐための警告。

    リストが読めない/空だと INTEL 検知は黙って無効になる（取得失敗時
    は旧ファイルを守る設計なので、鮮度の劣化も同じ形で現れる）。
    有効化されているのに使えない状態は、検知の不在ではなく故障と
    して通知する。警告は1日1回まで（identity="system" で記録）。
    """
    findings = []
    if not CONFIG["intel"]["enabled"]:
        return findings
    path = CONFIG["intel"]["path"]
    try:
        mtime = os.path.getmtime(path)
    except OSError:
        mtime = None
    if mtime is None or not load_intel_domains():
        if not already_alerted(conn, "system", "INTEL_HEALTH", "missing",
                               now, days=1):
            findings.append(
                ("system", "INTEL_HEALTH", ["missing"],
                 "■ 警告: インテルリストが読めない/空のため INTEL 検知が"
                 "無効です: %s" % path))
    elif now - mtime > INTEL_STALE_HOURS * 3600:
        if not already_alerted(conn, "system", "INTEL_HEALTH", "stale",
                               now, days=1):
            findings.append(
                ("system", "INTEL_HEALTH", ["stale"],
                 "■ 警告: インテルリストが %d 時間更新されていません"
                 "（intel_fetch のタイマーを確認）"
                 % int((now - mtime) // 3600)))
    return findings


def check_new_pair_burst(conn, now, skip_identities=frozenset()):
    """新規宛先バースト: 24hの新規宛先の「数」そのものを見る。

    NEW_PAIR は宛先ごとに2回以上を要求するため、多数の新規宛先へ
    1回ずつという無差別な型（探索・列挙）ですり抜ける。ここでは
    NEW_PAIR と同じ「機器らしい」適格条件の端末に限って件数で拾う。
    人間の端末は日常的に100件超の新規宛先を踏むので対象にしない。
    """
    findings = []
    rows = conn.execute(
        """
        SELECT identity, COUNT(*) AS n FROM id_pairs
        WHERE first_seen >= ? AND domain LIKE '%.%'
          AND (SELECT COUNT(*) FROM id_pairs q
               WHERE q.identity = id_pairs.identity AND q.last_seen >= ?
                 AND q.first_seen < ?) <= ?
        GROUP BY identity HAVING n >= ?
        ORDER BY n DESC
        """,
        (now - DAY, now - CONFIG["new_pair_window_days"] * DAY,
         now - ESTABLISHED_DAYS * DAY,
         CONFIG["new_pair_max_client_pairs"],
         CONFIG["new_pair_burst_threshold"]),
    ).fetchall()
    for ident, n in rows:
        if ident in skip_identities:
            continue
        if _identity_matches_ips(conn, ident, CONFIG["ignore_new_pair"]):
            continue
        akey = datetime.fromtimestamp(now, JST).strftime("%Y-%m-%d")
        if already_alerted(conn, ident, "NEW_PAIR_BURST", akey, now, days=1):
            continue
        top = [r[0] for r in conn.execute(
            "SELECT domain FROM id_pairs WHERE identity = ? "
            "AND first_seen >= ? ORDER BY recent_count DESC LIMIT 5",
            (ident, now - DAY)).fetchall()]
        findings.append((ident, "NEW_PAIR_BURST", [akey],
                         "■ 新規宛先バースト %s: 24hで新規 %d件（%s）"
                         % (identity_label(conn, ident), n,
                            "、".join(_defang(d) for d in top))))
    return findings


def _median(values):
    s = sorted(values)
    n = len(s)
    if n == 0:
        return 0.0
    return s[n // 2] if n % 2 else (s[n // 2 - 1] + s[n // 2]) / 2.0


def check_trend(conn, now):
    """緩やかな増加（徐汚染）の検知。通知のみ（報告対象にしない）。

    短窓 vs 直近平常の比較は、2 週間以上かけた坂を平常側に取り込む。
    ここでは 10 日バケットの傾きそのものを見る。対象は NEW_PAIR と
    同じ適格（確立済みの宛先種類が上限以下＝機器らしい端末）
    かつ、既知になってから TREND_MIN_AGE_DAYS 以上経った端末だけ。
    人の端末は利用の増加が正常なので構造的に入ってこないし、
    新規端末は「ゼロから増えている」ようにしか見えないので年齢で
    除外する。IoT の正常な変化は階段型（水準が変わって平ら）で、
    坂が続くこと自体が異常の形、という前提の検知。
    """
    findings = []
    window = CONFIG["new_pair_window_days"] * DAY
    cap = CONFIG["new_pair_max_client_pairs"]
    eligible = {r[0] for r in conn.execute(
        "SELECT identity FROM id_pairs WHERE last_seen >= ? "
        "AND first_seen < ? "
        "GROUP BY identity HAVING COUNT(*) <= ?",
        (now - window, now - ESTABLISHED_DAYS * DAY, cap)).fetchall()}
    first_seen = dict(conn.execute(
        "SELECT identity, first_seen FROM id_clients").fetchall())
    ignores = CONFIG["ignore_new_pair"]
    series = _id_hourly_series(conn)
    today = datetime.fromtimestamp(now, JST).date()

    def day_total(per, day):
        start = int(datetime(day.year, day.month, day.day,
                             tzinfo=JST).timestamp())
        return _series_sums(per, start, start + DAY)[0]

    for ident in sorted(eligible):
        fs = first_seen.get(ident)
        if fs is None or fs > now - TREND_MIN_AGE_DAYS * DAY:
            continue
        if ignores and _identity_matches_ips(conn, ident, ignores):
            continue
        per = series.get(ident, {})

        # 通信量: 10 日 × 3 バケットの日次中央値の傾き
        medians = []
        for b in range(TREND_VOL_BUCKETS):
            newest = today - timedelta(days=b * TREND_BUCKET_DAYS)
            days = [newest - timedelta(days=i)
                    for i in range(TREND_BUCKET_DAYS)]
            medians.append(_median([day_total(per, d) for d in days]))
        medians.reverse()  # 古い順
        if (medians[0] > 0
                and all(medians[i + 1] >= TREND_VOL_STEP * medians[i]
                        for i in range(len(medians) - 1))
                and medians[-1] >= TREND_VOL_TOTAL * medians[0]
                and medians[-1] >= TREND_VOL_MIN
                and not already_alerted(conn, ident, "TREND", "volume",
                                        now, days=TREND_SUPPRESS_DAYS)):
            findings.append(
                (ident, "TREND", ["volume"],
                 "■ 緩やかな増加 %s: 通信量の10日中央値が %s と増加継続"
                 "（徐汚染の型）"
                 % (identity_label(conn, ident),
                    " → ".join("%g" % m for m in medians))))

        # 宛先種類: 10 日 × 4 バケットの新規宛先数の傾き
        counts = []
        for b in range(TREND_DST_BUCKETS):
            end = now - b * TREND_BUCKET_DAYS * DAY
            start = end - TREND_BUCKET_DAYS * DAY
            counts.append(conn.execute(
                "SELECT COUNT(*) FROM id_pairs WHERE identity = ? "
                "AND first_seen >= ? AND first_seen < ?",
                (ident, start, end)).fetchone()[0])
        counts.reverse()  # 古い順
        if (all(counts[i + 1] > counts[i]
                for i in range(len(counts) - 1))
                and counts[-1] >= TREND_DST_MIN_LAST
                and counts[-1] >= TREND_DST_TOTAL * max(counts[0], 1)
                and not already_alerted(conn, ident, "TREND",
                                        "destinations", now,
                                        days=TREND_SUPPRESS_DAYS)):
            findings.append(
                (ident, "TREND", ["destinations"],
                 "■ 緩やかな増加 %s: 新規宛先数が10日毎に %s と増加継続"
                 % (identity_label(conn, ident),
                    " → ".join(str(c) for c in counts))))
    return findings


CANARY_DOMAIN = "canary.activeban.invalid"


def _device_for_identity(conn, identity):
    """identity から activeban の device {mac, ip, name} を組み立てる。"""
    if identity.startswith("mac:"):
        mac = identity[4:].upper()
        row = conn.execute(
            "SELECT ip FROM ip_mac WHERE mac = ? ORDER BY last_seen DESC LIMIT 1",
            (mac,),
        ).fetchone()
        if not row:
            # ip_mac（現在の対応）に無い MAC は、履歴の最新区間から拾う。
            # 複数インタフェースの端末では現在の行が別 MAC を指していて
            # ip=None になることがある（実例: 開発用 PC の第2 MAC）。
            row = conn.execute(
                "SELECT ip FROM ip_mac_history WHERE upper(mac) = ? "
                "ORDER BY valid_from DESC LIMIT 1",
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
    if kind == "INTEL":
        listed = load_intel_domains()
        hits = []
        for domain, count in conn.execute(
                "SELECT domain, recent_count FROM id_pairs "
                "WHERE identity = ? AND last_seen >= ? "
                "ORDER BY recent_count DESC", (identity, now - DAY)):
            entry = intel_match(domain, listed)
            if entry:
                hits.append({"domain": domain, "listed_entry": entry,
                             "count": count})
        if not hits:
            return None
        return {"device": device, "trigger": "intel",
                "reason": ("threat intel match: %s listed in %s"
                           % (hits[0]["domain"], CONFIG["intel"]["name"])),
                "ttl": CONFIG["activeban"]["ttl_seconds"],
                "evidence": {
                    "intel": {"list": CONFIG["intel"]["name"],
                              "hits": hits[:10]},
                    "recent": {"window_seconds": DAY,
                               "counts": {"queries": sum(
                                   h["count"] for h in hits)}},
                    "baseline": baseline}}
    if kind == "NEW_PAIR_BURST":
        n = conn.execute(
            "SELECT COUNT(*) FROM id_pairs WHERE identity = ? "
            "AND first_seen >= ? AND domain LIKE '%.%'",
            (identity, now - DAY)).fetchone()[0]
        top = [r[0] for r in conn.execute(
            "SELECT domain FROM id_pairs WHERE identity = ? "
            "AND first_seen >= ? ORDER BY recent_count DESC LIMIT 10",
            (identity, now - DAY)).fetchall()]
        return {"device": device, "trigger": "behavior",
                "reason": ("new-destination burst: %d new domains in 24h"
                           % n),
                "ttl": CONFIG["activeban"]["ttl_seconds"],
                "evidence": {
                    "recent": {"window_seconds": DAY, "new_pair_count": n,
                               "top_new_domains": top},
                    "baseline": baseline}}
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


def queue_bridge_events(conn, findings, now):
    """危険シグナルとカナリアを bridge_outbox に積む（state と同一トランザクション）。

    送信そのものは commit 後の flush_bridge_outbox が担う。検知の記録と
    「送るべきイベント」を同じトランザクションで確定させることで、
    Talk 通知の成否や送信の一時失敗でイベントが消えたり、記録だけが
    進んで二度と送られない、という事故を構造的に無くす。
    戻り値は積んだ件数。
    """
    cfg = CONFIG["activeban"]
    if not cfg["enabled"]:
        return 0
    queued = 0
    for identity, kind, _akeys, _text in findings:
        if kind not in cfg["report_kinds"]:
            continue
        event = build_activeban_event(conn, identity, kind, now)
        if event is None:
            continue
        conn.execute(
            "INSERT INTO bridge_outbox (queued_at, identity, kind, event) "
            "VALUES (?, ?, ?, ?)",
            (now, identity, kind, json.dumps(event, ensure_ascii=False)))
        queued += 1
    if cfg["canary"]:
        for identity, domain, count in check_canary(conn, now):
            event = build_canary_event(conn, identity, domain, count)
            conn.execute(
                "INSERT INTO bridge_outbox (queued_at, identity, kind, event) "
                "VALUES (?, ?, ?, ?)",
                (now, identity, "CANARY",
                 json.dumps(event, ensure_ascii=False)))
            # 再送抑制は「積んだ時点」で記録する。送信リトライは outbox が
            # 担うので、抑制が先に効いてもイベントは失われない。
            record_alert(conn, identity, "CANARY", domain, now)
            queued += 1
    return queued


def flush_bridge_outbox(conn):
    """bridge_outbox を古い順に送信し、成功した行だけ消す。例外は投げない。

    失敗した行は attempts と last_error を残して次回実行で再試行する。
    Talk 通知とは完全に独立で、片方の失敗がもう片方を止めない。
    戻り値は (送信成功数, 残数)。
    """
    rows = conn.execute(
        "SELECT id, identity, kind, event FROM bridge_outbox ORDER BY id"
    ).fetchall()
    sent = 0
    for row_id, identity, kind, event_json in rows:
        try:
            res = send_activeban(json.loads(event_json))
            print("activeban report (%s, %s): %s"
                  % (identity, kind, json.dumps(res, ensure_ascii=False)),
                  file=sys.stderr)
            conn.execute("DELETE FROM bridge_outbox WHERE id = ?", (row_id,))
            conn.commit()
            sent += 1
        except Exception as e:
            conn.execute(
                "UPDATE bridge_outbox SET attempts = attempts + 1, "
                "last_error = ? WHERE id = ?",
                (str(e)[:200], row_id))
            conn.commit()
            print("activeban report failed (%s, %s): %s"
                  % (identity, kind, e), file=sys.stderr)
    remaining = conn.execute(
        "SELECT COUNT(*) FROM bridge_outbox").fetchone()[0]
    return sent, remaining


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


def _talk_spool_path():
    """未配信の Talk メッセージを溜めるスプール（state DB と同じディレクトリ）。"""
    return os.path.join(os.path.dirname(CONFIG["state_path"]),
                        "talk_spool.jsonl")


def spool_talk(message, now):
    """Talk に届かなかったメッセージをスプールへ verbatim で積む。"""
    path = _talk_spool_path()
    with open(path, "a", encoding="utf-8") as f:
        f.write(json.dumps({"ts": now, "message": message},
                           ensure_ascii=False) + "\n")


def flush_talk_spool():
    """スプールを古い順に全て送る。1件でも失敗したら残りを残して例外にする。

    呼び出し側は「スプールが空でなければ Talk は不調」と判断できる。
    順序を守るため、失敗した時点で打ち切り、未送信分はファイルを
    書き戻す（ha_monitor の通知スプールと同じ運用型）。
    """
    path = _talk_spool_path()
    if not os.path.exists(path):
        return
    with open(path, encoding="utf-8") as f:
        lines = [ln for ln in f.read().splitlines() if ln.strip()]
    sent = 0
    try:
        for ln in lines:
            post_talk(json.loads(ln)["message"])
            sent += 1
    finally:
        rest = lines[sent:]
        if rest:
            with open(path, "w", encoding="utf-8") as f:
                f.write("\n".join(rest) + "\n")
        elif os.path.exists(path):
            os.unlink(path)
    if sent < len(lines):
        raise RuntimeError("Talk spool flush incomplete: %d/%d"
                           % (sent, len(lines)))


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


def prune_state(conn, now):
    """古い履歴を捨てる。ベースラインは「最近の姿」であって生涯記録ではない。

    pairs / id_pairs は last_seen が保持期間（既定180日）を超えた行を、
    hourly は夜間判定が参照する数週間分（既定40日）を残して削除する。
    保持期間を長く取ってあるので、消えた宛先の再出現が「新規」として
    光るのは稀で、意味論としても正しい（半年消えていた宛先は新規同然）。
    破壊的なので dry-run では実行しない。
    """
    pair_cut = now - CONFIG["retention_days"] * DAY
    conn.execute("DELETE FROM pairs WHERE last_seen < ?", (pair_cut,))
    conn.execute("DELETE FROM id_pairs WHERE last_seen < ?", (pair_cut,))
    hour_cut = now - CONFIG["hourly_retention_days"] * DAY
    conn.execute("DELETE FROM hourly WHERE hour < ?", (hour_cut,))


def run(now, bootstrap=False, dry_run=False):
    global HONOR_ALERTS
    # dry-run はプレビュー専用: alerts の抑制を見ず、今マッチする所見を
    # 全部出す（記録もしない）。本番実行の検証が抑制に邪魔されないため。
    HONOR_ALERTS = not dry_run
    span = BOOTSTRAP_DAYS * DAY if bootstrap else RECENT_HOURS * HOUR
    start, end = now - span, now
    if not bootstrap:
        # 窓の開始を時間境界に切り下げる。部分的な先頭バケットが hourly
        # の確定値を上書きして痩せさせるのを防ぐ（収集は最大で1時間弱
        # 長くなるが、merge は時間帯ごとの確定値の置換なので安全）。
        start -= start % HOUR

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

        if not dry_run:
            prune_state(conn, now)

        findings = []
        findings += check_new_clients(conn, now)
        new_ids = {f[0] for f in findings if f[1] == "NEW_CLIENT"}
        findings += check_new_pairs(
            conn, now, skip_identities=new_ids | known_released_identities(conn, now)
        )
        findings += check_nx_spike(conn, now)
        findings += check_night(conn, now)
        findings += check_intel(conn, now)
        findings += check_intel_health(conn, now)
        findings += check_new_pair_burst(
            conn, now,
            skip_identities=new_ids | known_released_identities(conn, now))
        findings += check_trend(conn, now)
        # リゾルバ自身 (127.0.0.1 等) は「クライアント」ではない。FTL が
        # 端末のホスト名を引く PTR 問い合わせ等がここに出るため丸ごと外す。
        findings = [f for f in findings if f[0] not in SELF_IPS]
        if CONFIG["ignore_clients"]:
            findings = [
                f for f in findings
                if f[1] == "NEW_CLIENT"
                or not _identity_matches_ips(conn, f[0], CONFIG["ignore_clients"])
            ]

        if dry_run:
            # プレビュー専用: 外部送信（Talk / 橋渡し / スプール処理）は
            # 一切しない。state は進めるが alerts は記録しない（調整用）。
            # （以前は no-findings 分岐だけ dry_run を見ておらず、カナリア
            # 経由で本物の BAN を飛ばし得た。ここで一元化して防ぐ。）
            if findings:
                print("[dns_watch] DNSベースライン逸脱を検知\n"
                      + "\n".join(f[3] for f in findings))
            conn.commit()
            return 0

        # 検知の記録と橋渡しイベントを同一トランザクションで確定させる。
        # この commit 以降は、どの配信が失敗しても記録が巻き戻って
        # 再検知したり、イベントだけが消えたりしない（通知と橋渡しの独立化）。
        queue_bridge_events(conn, findings, now)
        for client, kind, akeys, _text in findings:
            for akey in akeys:
                record_alert(conn, client, kind, akey, now)
        conn.commit()

        # commit 後の配信は互いに独立。橋渡しは outbox から送り、失敗分は
        # 次回実行で再試行する。Talk はスプール（過去の未配信分）を先に
        # 流し、今回分が届かなければスプールへ積んで exit 2 で知らせる。
        flush_bridge_outbox(conn)
        talk_ok = True
        try:
            flush_talk_spool()
        except Exception as e:
            print("dns_watch: Talk spool flush failed: %s" % e,
                  file=sys.stderr)
            talk_ok = False
        if findings:
            message = ("[dns_watch] DNSベースライン逸脱を検知\n"
                       + "\n".join(f[3] for f in findings))
            if talk_ok:
                try:
                    post_talk(message)
                except Exception as e:
                    print("dns_watch: Talk POST failed, spooled: %s" % e,
                          file=sys.stderr)
                    spool_talk(message, now)
                    talk_ok = False
            else:
                spool_talk(message, now)
        push_kuma_heartbeat()
        return 0 if talk_ok else 2
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def push_kuma_heartbeat():
    """Uptime Kuma のプッシュモニタへ生存通知を送る（任意設定）。

    送るのは本レーンが正常完了したときだけ。高速レーンからは送らない
    （本レーンの死を高速レーンの生存で隠してしまうため）。プッシュが
    途絶えたら Kuma 側が「監視が死んだ」と判断する — 2026-11 の
    3.5日間の無言死への対策。失敗しても実行結果には影響させない
    （監視の監視が本隊を道連れにしない）。
    """
    url = (CONFIG.get("kuma") or {}).get("push_url")
    if not url:
        return
    sep = "&" if "?" in url else "?"
    full = url + sep + "status=up&msg=OK&ping="
    try:
        with urllib.request.urlopen(full, timeout=5) as resp:
            resp.read()
    except Exception as e:
        print("dns_watch: Kuma push failed: %s" % e, file=sys.stderr)


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
    except Exception as e:  # 収集の失敗は state を進めず exit 2
        print("dns_watch: %s" % e, file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
