#!/usr/bin/env python3
"""lanlookout fast lane: canary + NX-burst detection on a short window.

The main dns_watch run is a 30-minute batch over a 25-hour window: good
for baselines, but a tripwire signal (the activeban canary) or a sudden
NXDOMAIN burst (DGA-style behaviour) should not wait for it. This script
reuses the same collector and the same activeban bridge, but looks only
at the last WINDOW seconds and checks only those two signals:

  - canary: any query for canary.activeban.invalid or a subdomain
  - NX burst: >= NX_BURST_MIN NXDOMAIN replies and >= NX_BURST_RATIO of
    all queries from one device inside the window; the report evidence
    carries the top NX domains and the distinct NX domain count, so
    the verifier can tell OS resolver noise from DGA-shaped labels

It keeps no baseline state. Suppression timestamps live in a small JSON
file next to the main state DB (fastlane_state.json); an event is only
marked suppressed after a successful send, so a failed send is retried
on the next run instead of being lost. Events whose device MAC cannot
be resolved are skipped: enforcement is MAC-keyed, and a guessed
identity must never be reported (see docs/integration.md).

Notifications are left to activeban itself (it announces bans and
releases on Talk). The main lane will usually re-report the same
canary later from its own window; that is harmless (a duplicate ban
extends the TTL, a protected MAC is refused again).

Config: the same lanlookout config.json as dns_watch (the activeban
section gates everything). Usage: fastlane.py [--dry-run]
"""

import importlib.util
import json
import os
import sqlite3
import sys
import time

_HERE = os.path.dirname(os.path.abspath(__file__))
_spec = importlib.util.spec_from_file_location(
    "dns_watch", os.path.join(_HERE, "dns_watch.py"))
dw = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(dw)

WINDOW = 900                # 直近15分だけを見る
NX_BURST_MIN = 20           # 窓内の NXDOMAIN 最低件数
NX_BURST_RATIO = 0.5        # 窓内の NXDOMAIN 最低率
CANARY_SUPPRESS = 3600      # (mac, domain) 単位の再送抑制: 1時間
NX_SUPPRESS = 3600          # 端末単位の再送抑制: 1時間

CANARY_DOMAIN = dw.CANARY_DOMAIN


# ------------------------------------------------------------------ 抑制

def _state_file():
    return os.path.join(os.path.dirname(dw.CONFIG["state_path"]),
                        "fastlane_state.json")


def load_suppression():
    try:
        with open(_state_file(), encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def save_suppression(data, now):
    # 1日より古い抑制は捨てる（ファイルが育ち続けないように）。
    data = {k: v for k, v in data.items() if now - v < 86400}
    path = _state_file()
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f)
    os.replace(tmp, path)


def _suppressed(data, key, now, window):
    return now - data.get(key, 0) < window


# ------------------------------------------------------------------ 同定

def load_ip_mac():
    """本レーンが学習した ip_mac を state DB から読み取り専用で引く。"""
    out = {}
    try:
        conn = sqlite3.connect("file:%s?mode=ro" % dw.CONFIG["state_path"],
                               uri=True)
        try:
            for ip, mac in conn.execute("SELECT ip, mac FROM ip_mac"):
                out[ip] = mac.lower()
        finally:
            conn.close()
    except sqlite3.Error:
        pass
    return out


# ループバックは LAN の端末ではない。本レーンは本線 run() の
# SELF_IPS フィルタを通らないので、ここで同じ除外を効かせる。
_NULL_MACS = {"00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff"}


def _is_self_ip(ip):
    return ip in dw.SELF_IPS or ip.startswith("127.")


def resolve_mac(ip, info, ip_mac):
    mac = ip_mac.get(ip) or (info.get(ip) or {}).get("mac") or ""
    mac = mac.lower()
    if not dw._MAC_RE.match(mac) or mac in _NULL_MACS:
        # 形式は合っていても全ゼロ/ブロードキャストは端末の MAC では
        # ない（FTL は 127.0.0.1 の MAC として全ゼロを返す）。
        # 「解決できない」として扱い、推測で報告しない。
        return ""
    return mac


# ------------------------------------------------------------------ 検知

def find_canary(pairs, info, ip_mac, suppressed, now):
    """canary 宛のペアを (mac, ip, name, domain, count) で返す。"""
    out = []
    for (ip, domain), (count, _nx, _f, _l) in pairs.items():
        if _is_self_ip(ip):
            continue
        if domain != CANARY_DOMAIN and not domain.endswith("." + CANARY_DOMAIN):
            continue
        mac = resolve_mac(ip, info, ip_mac)
        if not mac:
            print("fastlane: canary from %s skipped (no MAC)" % ip,
                  file=sys.stderr)
            continue
        if _suppressed(suppressed, "canary|%s|%s" % (mac, domain),
                       now, CANARY_SUPPRESS):
            continue
        name = (info.get(ip) or {}).get("name", "")
        out.append((mac, ip, name, domain, count))
    return out


def find_nx_burst(pairs, info, ip_mac, suppressed, now):
    """端末単位で窓内の (合計, NX) を集め、バーストを返す。

    戻り値には NX のドメイン内訳（上位と相異数）も含める。件数と率
    だけでは、判定側が「OS の名前解決ノイズ（サフィックス探索や
    WPAD 等）」と「DGA 型のランダムラベル」を区別できないため。
    """
    per = {}
    nx_domains = {}
    for (ip, domain), (count, nx, _f, _l) in pairs.items():
        a = per.setdefault(ip, [0, 0])
        a[0] += count
        a[1] += nx
        if nx > 0:
            nx_domains.setdefault(ip, []).append((domain, nx))
    out = []
    for ip, (total, nx) in per.items():
        if _is_self_ip(ip):
            continue
        if nx < NX_BURST_MIN or total == 0 or nx / total < NX_BURST_RATIO:
            continue
        mac = resolve_mac(ip, info, ip_mac)
        if not mac:
            print("fastlane: NX burst from %s skipped (no MAC)" % ip,
                  file=sys.stderr)
            continue
        if _suppressed(suppressed, "nx|%s" % mac, now, NX_SUPPRESS):
            continue
        name = (info.get(ip) or {}).get("name", "")
        doms = sorted(nx_domains.get(ip, []), key=lambda t: -t[1])
        out.append((mac, ip, name, total, nx, doms[:10], len(doms)))
    return out


# ------------------------------------------------------------------ 送信

def canary_event(mac, ip, name, domain, count):
    test_id = ""
    if domain != CANARY_DOMAIN:
        test_id = domain[: -len(CANARY_DOMAIN)].rstrip(".").split(".")[0]
    return {"device": {"mac": mac, "ip": ip, "name": name},
            "trigger": "canary", "reason": "canary test probe (fast lane)",
            "ttl": dw.CONFIG["activeban"]["canary_ttl_seconds"],
            "evidence": {"canary_domain": domain, "test_id": test_id,
                         "recent": {"window_seconds": WINDOW,
                                    "counts": {"queries": count}}}}


def nx_event(mac, ip, name, total, nx, top_nx=(), nx_distinct=0):
    ratio = round(nx / total, 4) if total else 0.0
    return {"device": {"mac": mac, "ip": ip, "name": name},
            "trigger": "behavior",
            "reason": ("NXDOMAIN burst (fast lane): %d NX of %d queries "
                       "in %d min (%.0f%%)"
                       % (nx, total, WINDOW // 60, ratio * 100)),
            "ttl": dw.CONFIG["activeban"]["ttl_seconds"],
            "evidence": {"recent": {"window_seconds": WINDOW,
                                    "counts": {"queries": total, "nx": nx},
                                    "nx_ratio": ratio,
                                    "top_nx_domains": [
                                        {"domain": d, "nx": c}
                                        for d, c in top_nx],
                                    "nx_distinct_domains": nx_distinct},
                         "baseline": None,
                         "baseline_note": "fast lane: short window, "
                                          "no baseline attached"}}


def run(now, dry_run=False):
    cfg = dw.CONFIG["activeban"]
    if not cfg["enabled"]:
        print("fastlane: activeban bridge disabled; nothing to do",
              file=sys.stderr)
        return 0
    data = dw.collect_all(now - WINDOW, now)
    pairs, info = data["pairs"], data["client_info"]
    ip_mac = load_ip_mac()
    suppressed = load_suppression()
    sent = 0
    jobs = []
    if cfg["canary"]:
        for mac, ip, name, domain, count in find_canary(
                pairs, info, ip_mac, suppressed, now):
            jobs.append(("canary|%s|%s" % (mac, domain),
                         canary_event(mac, ip, name, domain, count)))
    if "NX_SPIKE" in cfg["report_kinds"]:
        for mac, ip, name, total, nx, top_nx, nx_distinct in find_nx_burst(
                pairs, info, ip_mac, suppressed, now):
            jobs.append(("nx|%s" % mac,
                         nx_event(mac, ip, name, total, nx,
                                  top_nx, nx_distinct)))
    for key, event in jobs:
        if dry_run:
            print("fastlane dry-run: %s"
                  % json.dumps(event, ensure_ascii=False), file=sys.stderr)
            sent += 1
            continue
        try:
            res = dw.send_activeban(event)
        except Exception as e:
            # 抑制を記録しないので、次回実行で再試行される。
            print("fastlane: send failed (%s): %s" % (key, e),
                  file=sys.stderr)
            continue
        print("fastlane report (%s): %s"
              % (key, json.dumps(res, ensure_ascii=False)), file=sys.stderr)
        suppressed[key] = now
        sent += 1
    if not dry_run:
        save_suppression(suppressed, now)
    return sent


def main(argv):
    dry_run = "--dry-run" in argv
    run(int(time.time()), dry_run=dry_run)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
