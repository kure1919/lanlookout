# lanlookout

A **read-only baseline anomaly monitor for a home LAN** — the
lookout on the wall. Today its sensor is DNS (Pi-hole); the design
takes further sensors (router flow data, e.g. from an OpenWrt
gateway) without changing what the system *is*: per-device
behavioural baselines, and a voice when a device steps outside its
own.

It watches what every device on your network usually does, learns
the baseline, and speaks up when a device steps outside it — with
numbers, not vibes. It stands on its own as a notification system;
nothing else is required.

It can also *report* its dangerous signals to
[activeban](https://github.com/kure1919/activeban), the author's
companion ban controller — but that is an optional output, not its
identity. activeban's side of the contract is deliberately generic:
any detector that reports in the documented JSON shape can drive it,
and lanlookout is simply one such detector.

> **Status: experimental "utakata" project** — *utakata* (泡沫) is foam
> on water: here today, gone tomorrow. Built for the author's own home,
> published in case it is useful to someone. Maintenance is best-effort
> and may stop at any time. No promotion, no roadmap.

## What it detects

Per device (identity is **MAC-first**: IP↔MAC history is tracked over
time, so a DHCP move does not make a known device "new", and a recycled
IP does not inherit another device's history):

| Signal | Meaning | Reportable to activeban? |
|---|---|---|
| `NEW_CLIENT` | A device that was not in the baseline appeared | No — discovery |
| `NEW_PAIR` | A machine-like device (small destination set) queried a domain it never queried before | No — discovery |
| `NX_SPIKE` | NXDOMAIN count/ratio jumped far above the device's own baseline (DGA / misconfiguration signature) | **Yes** |
| `NIGHT` | 00:00–05:00 traffic far above the device's previous busiest night | No (configurable) |
| canary | A query for `*.canary.activeban.invalid` | **Yes** (test probe) |

Discovery signals are deliberately **not** ban triggers. New is not
dangerous; *quantitatively abnormal* is. When the optional activeban
bridge is enabled, only `NX_SPIKE` is reported by default, and the
report carries the evidence a review needs: a counted `recent` block
(24 h query/NX counts, ratios, new destinations) and a `baseline`
block (30-day median volume, NX rate, established top domains)
computed from the same state the detection used.

Notifications go to Nextcloud Talk (or stdout when unconfigured).
Domains in notifications are defanged (`example[.]com`) so chat
clients do not auto-fetch the very domains being reported.

Delivery of the two outputs is independent by design. Detection
results and bridge events are committed to the state database in one
transaction; Talk posting and bridge sending happen afterwards,
separately. A Talk outage can no longer suppress a report, and a
failed report can no longer be silently dropped: undelivered Talk
messages are queued verbatim in `talk_spool.jsonl` next to the state
database and flushed first on the next run, and undelivered bridge
events stay in a `bridge_outbox` table in the state database and are
retried on every run until the receiver accepts them.

## How it collects

Nothing is installed on the Pi-hole nodes. Every run, `dns_watch.py`
pushes `pihole_collect.py` over SSH to each node; the collector reads
the Pi-hole FTL database **read-only** and returns aggregates (pairs,
hourly counts) as JSON. Raw queries never leave the node. Multiple
nodes (e.g. a redundant pair) are merged before analysis.

The monitor itself is read-only: it never changes Pi-hole, DHCP, or
firewall state. The optional activeban bridge is append-only
reporting over an SSH forced command — a one-way output, like the
Talk notification, that cannot reach back into the monitor.

### Device identity and its limits

Devices are identified by MAC address (learned from the Pi-hole data
and ARP), because IPs are reassigned by DHCP. Two honest limits:

- Attribution is an approximation. Collection aggregates by IP, so
  when an IP changes hands inside a collection window, the window's
  traffic is attributed to the device that held the IP at the first
  query. DHCP reservations for fixed devices keep this rare in
  practice; treat identity as strong evidence, not proof.
- MACs can be randomized and spoofed. Phones randomize per network
  by default (stable on your own SSID, so home devices stay
  trackable), and a device already on the LAN can spoof another
  device's MAC. An attacker doing that is an active, targeted
  adversary — outside what this system is designed to handle.

## The canary probe

If the activeban bridge is enabled, the whole response chain can be
tested end to end (DNS observation → detection → report → ban → LLM
review → release) with no new listener: open
`http://canary.activeban.invalid/` on any device that uses the
Pi-hole. The lookup fails (`.invalid` never resolves); lanlookout
sees the query and reports it as `trigger: "canary"`, TTL 300 s.
Without the bridge, the probe name is just an ordinary failed lookup
and nothing is reported.

The probe's design and the receiving side are specified in §7
("Canary test probe") of
[activeban's integration guide](https://github.com/kure1919/activeban/blob/main/docs/integration.md).

## Companions in this repo

- `dns_watch.py` — the monitor (single file, stdlib only)
- `pihole_collect.py` — the on-node collector (read-only FTL queries)
- `dns_audit.py` — a one-shot full-history audit: cross-checks the
  whole FTL retention window (e.g. 91 days) against threat-intel and
  structural screening and writes a Markdown report. It answers "has
  anything in this house been talking to something bad, historically?"
  once, before you decide to automate responses. **Read its header
  before running**: it streams by design because the author's monitor
  host has 1 GB of RAM; a bulk in-memory version of this audit froze
  that box. That lesson is part of the tool.

## Quick start

Shortcut: `sh install.sh` (run as the user who will run the monitor)
creates the config and state directories, copies the example config,
and generates + installs the systemd units with your user name and
install path substituted. Steps 2, 3 and 6 below are what it does;
the rest is the same either way.

1. Python 3 on the monitoring host; SSH access to your Pi-hole
   node(s) for a user that can read the FTL database (or use sudo:
   `use_sudo`).
2. Copy `examples/config.example.json` to
   `~/.config/lanlookout/config.json` and set `nodes`, `ssh_user`,
   `ftl_db`. (`DNS_WATCH_CONFIG` overrides the path.)
3. Optionally copy `examples/nextcloud-config.example.json` to
   `~/.config/lanlookout/nextcloud.json` (or set
   `DNS_WATCH_NEXTCLOUD_CONFIG`) for Talk notifications; without it,
   findings are printed to stdout.
4. Optionally create `device_names.json` (MAC → human name, see
   `examples/device_names.example.json`) so notifications say
   "Living room bulb" instead of an IP. Key by MAC: IPs rot under
   DHCP, and a stale IP→name map misidentifies devices in security
   notifications.
5. Seed the baseline (no notifications are sent):

   ```sh
   python3 dns_watch.py --bootstrap   # builds 30 days of baseline
   python3 dns_watch.py --dry-run     # preview what would fire now
   python3 dns_watch.py               # a normal run
   ```

6. Run it every 30 minutes (the `lanlookout.timer` unit template is
   in `systemd/`; `install.sh` generates the real unit from it).
   If notification delivery fails, the run exits non-zero **without
   advancing state**, so the next run retries — alerts are not lost.
7. Optional — to also report to an activeban host: in `config.json`,
   set `activeban.enabled` and `activeban.ssh_host` to that host's
   forced-command account (see §2 of
   [activeban's integration guide](https://github.com/kure1919/activeban/blob/main/docs/integration.md)),
   and deploy the receiver there. Start with the canary: query
   `canary.activeban.invalid` from a test device and watch the full
   loop fire. lanlookout works exactly the same with this left off.

Thresholds are constants at the top of `dns_watch.py`, with comments
explaining how each was chosen. Device identity, alert suppression
windows, and the ignore lists (`ignore_clients`,
`ignore_new_pair`, `ignore_domain_patterns`) are all in the config
file; the config example documents each key.

## Privacy note

A household's DNS history is sensitive. The state database directory
is created mode `0700`, raw queries never leave the Pi-hole nodes, and
the real config / registry / state files are all in `.gitignore`.
What you do with the aggregates is your responsibility.

## License

MIT — see `LICENSE`.
