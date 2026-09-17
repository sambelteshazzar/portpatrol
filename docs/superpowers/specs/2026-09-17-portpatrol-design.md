# PortPatrol Design

Date: 2026-09-17
Status: Approved

## Purpose

Open ports are where network attacks begin. WannaCry spread through exposed SMB port 445 in May 2017 and infected 300,000+ machines across 150 countries; NHS hospitals turned away emergencies and losses reached an estimated $4 billion. Mirai scanned for open telnet (ports 23 and 2323) on IoT devices, enrolled them with factory credentials, and used roughly 900,000 infected devices to knock GitHub, Twitter, and Netflix offline through the Dyn DDoS in October 2016. Variants of Mirai now hunt ports 8080, 8443, 80, 81, and Android ADB (5555). CISA maintains the Known Exploited Vulnerabilities catalog with 1,700+ vulnerabilities exploited in the wild, most of them reachable through a listening network service.

PortPatrol scans the local machine for open TCP ports, classifies each open port against a knowledge base built from nmap service detection techniques, and warns the user through a desktop notification before an attacker finds the port first. It detects; it never exploits.

## Goals

1. Scan localhost TCP ports on demand and report each open port with its service, risk level, and hardening advice.
2. Fire native desktop notifications on Linux and Windows with emoji risk indicators.
3. Run on any Linux distribution and Windows 10/11 using Python 3.8+ standard library only. Zero pip dependencies.
4. Classify ports with an editable JSON knowledge base modeled on nmap's `nmap-service-probes` format.
5. Enrich results with `nmap -sV` when nmap is installed, and with the CISA KEV catalog when the user passes `--kev`.
6. Exit with meaningful codes so scripts and CI can react: 0 clean, 1 findings, 2 error.

## Non-Goals (v1)

- No scanning of other hosts. Local machine only.
- No background daemon, scheduler, or tray app. On-demand CLI only.
- No exploitation of any kind. Connect scans with per-port timeouts, read-only, rate-limited.
- No GUI. Console table plus desktop notifications.
- No machine learning. Rules are explainable and hand-curated.

## Architecture

```
portpatrol/
├── bin/portpatrol            # Bash launcher, installable on PATH
├── portpatrol/
│   ├── __init__.py
│   ├── cli.py                # argparse entry point: scan, explain
│   ├── scanner.py            # socket sweep, banner probes, nmap enrichment
│   ├── knowledge.py          # knowledge base loader and risk classifier
│   ├── knowledge_base.json   # port rules: service, probes, risk, advice, CVEs
│   ├── notifier.py           # cross-platform desktop notifications
│   └── report.py             # console table, --json output, history file
└── tests/
    ├── test_knowledge.py
    ├── test_scanner.py
    └── test_notifier.py
```

Each module has one job: `scanner.py` finds open ports and identifies services, `knowledge.py` classifies them, `notifier.py` alerts, `report.py` renders and persists. `cli.py` wires them together and owns argument parsing.

## Scan Engine

Two phases, run in order:

**Phase 1: Socket sweep.** A `concurrent.futures.ThreadPoolExecutor` (default 100 workers) opens TCP connections to each target port on 127.0.0.1 with a 0.5 second connect timeout. Ports that accept the connection are open; connection refused or permission denied means closed or filtered.

**Phase 2: Service identification.** For every open port, the scanner picks a probe from the knowledge base entry for that port:

- Banner-first services (SSH, FTP, SMTP) send a greeting on connect. The scanner reads the first 256 bytes with a 1 second timeout.
- Request-first services send nothing until asked. The scanner sends the entry's probe and reads the response: `HEAD / HTTP/1.0\r\n\r\n` for web ports, `PING\r\n` for Redis.
- Services with no probe and no banner stay `unknown`.

Each knowledge base entry carries regex `match` patterns in the style of nmap's `nmap-service-probes` file. The scanner applies them to the response bytes to extract service name and version. Example: pattern `^SSH-([\d.]+)-OpenSSH_([\d.p]+)` on an SSH banner yields service `ssh`, version `OpenSSH 8.9p1`.

**Optional nmap enrichment.** If `shutil.which("nmap")` finds nmap on PATH, the scanner runs `nmap -sV --version-light -p <ports> -oX - 127.0.0.1` and merges its service, version, and product fields into results where the socket probes found nothing. If nmap is missing, phase 2 output stands alone and `--verbose` notes the skip.

**Optional KEV enrichment.** With `--kev`, the scanner downloads the CISA KEV JSON feed (`https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`) once per run, caches it at `~/.portpatrol/kev.json` with a 24 hour freshness window, and matches the feed against detected services. Matching works two ways: the entry's `kev_hints` keywords are searched in the feed's `vendorProject` and `description` fields, and nmap-derived product names (when present) are searched the same way. Matching entries surface their CVE IDs in the report and notification. Without network access, the tool falls back to the cached file; with no cache, KEV enrichment is skipped with a note.

## Knowledge Base

`knowledge_base.json` ships with roughly 50 curated entries covering the ports that matter in real incidents. Schema per entry:

```json
{
  "port": 22,
  "protocol": "tcp",
  "service": "ssh",
  "risk": "info",
  "banner_first": true,
  "probe": null,
  "match": ["^SSH-([\\d.]+)-(OpenSSH_([\\d.p]+)|.*)"],
  "advice": "SSH is safe when keyed and patched. Disable password auth, disable root login, keep OpenSSH current.",
  "kev_hints": ["openssh"]
}
```

- `risk` is one of `critical`, `high`, `medium`, `info`, or `unknown`.
- `advice` follows CIS/NIST hardening practice: close unused ports, bind services to localhost, firewall default-deny, patch per KEV priority.
- Seed entries include: 21 FTP (high), 22 SSH (info), 23 Telnet (critical, Mirai vector), 25 SMTP (medium), 53 DNS (medium), 80/443 HTTP(S) (info), 135 RPC (high), 139 NetBIOS (high), 445 SMB (high), 5555 ADB (critical, Mirai vector), 1433 MSSQL (medium), 3306 MySQL (medium), 3389 RDP (high, BlueKeep path), 5432 PostgreSQL (medium), 5900 VNC (medium), 6379 Redis (critical when unauthenticated), 8080/8443 alt-web (medium, Mirai Wicked vector), 9200 Elasticsearch (high), 27017 MongoDB (critical when unauthenticated).
- Ports without entries classify as `unknown` with the banner-derived service guess.
- Resolution order: `~/.portpatrol/knowledge_base.json` (user override), package `portpatrol/knowledge_base.json` (ships with the defaults), then built-in Python defaults in `portpatrol/defaults.py`. First valid source wins.
- `top50` and `top100` presets resolve from a built-in curated top-100 port list shipped as package data, drawn from nmap's top-ports knowledge. `top1000` scans the full well-known range 1-1023 plus that top-100 list.
- The file is plain JSON. Users edit it without touching code. `portpatrol explain <port>` prints the entry for a port, or the unknown-port fallback.

## Notifications

One summary toast per scan, plus one per-port toast for `critical` findings only.

| Emoji | Risk | Trigger |
|-------|------|---------|
| ✅ | All clear | no open ports |
| 🔵 | Info | info-level findings only |
| 🟡 | Medium | highest finding is medium |
| ⚠️ | High | highest finding is high |
| 🚨 | Critical | highest finding is critical |
| ❓ | Unknown | only unknown ports found |

Summary example: `🚨 PortPatrol: 3 open ports — 1 critical, 1 high, 1 info`.

Delivery per platform:

- **Linux**: `notify-send` via `subprocess.run`. When `notify-send` is missing (headless servers, minimal WM setups), notifications degrade to the console report and the run still succeeds.
- **Windows**: a PowerShell toast via `Windows.UI.Notifications`, falling back to a `ctypes.windll.user32.MessageBoxW` dialog when the toast API is unavailable. Both paths are stdlib-only.
- Toast bodies carry Unicode emoji; both delivery paths render them.

## CLI Interface

```
portpatrol scan [--ports top50|top100|top1000|all|SPEC] [--json] [--kev] [--verbose] [--no-notify]
portpatrol explain <port>
```

- `--ports SPEC` accepts `80,443` and ranges `8000-8100`. Default is `top1000`.
- `--json` prints the machine-readable result to stdout and skips the console table (notifications still fire unless `--no-notify`).
- `--no-notify` suppresses desktop notifications for scripting.
- `--verbose` logs skipped enrichments, filtered ports, and probe failures to stderr.
- `explain` prints service, risk, advice, and CVE hints for one port and exits 0 whether or not the port is known.

## Result and History

Each run writes `~/.portpatrol/history.json`, appending a record with timestamp, target, scanned port count, and the open-port findings. `--json` output shape:

```json
{
  "timestamp": "2026-09-17T14:03:22Z",
  "target": "127.0.0.1",
  "scanned": 1000,
  "open": [
    {"port": 22, "service": "ssh", "version": "OpenSSH 9.6p1", "risk": "info", "cves": []},
    {"port": 6379, "service": "redis", "version": "7.2.4", "risk": "critical", "cves": []}
  ]
}
```

## Error Handling

- nmap missing: skip enrichment, note under `--verbose`.
- KEV fetch fails: use cache; no cache: skip with a note; scan still succeeds.
- Notification channel missing: console-only, exit code unchanged.
- Knowledge base file missing or invalid JSON: fall back to built-in defaults, warn on stderr.
- Ports refusing connections or denied by firewall: closed or filtered, not errors.
- Invalid port spec: argparse error, exit 2.
- No open ports: all-clear toast, exit 0.

## Security Posture of the Tool Itself

- Connect scans only. No SYN floods, no packet crafting, no exploitation, no credential attempts.
- Read-only against the host except for the history, cache, and knowledge base files under `~/.portpatrol/`.
- Probe strings are fixed and rate-limited: one probe per open port per scan.
- The tool never sends findings anywhere. No telemetry, no phone-home beyond the user-triggered `--kev` fetch from cisa.gov.

## Testing

- `tests/test_knowledge.py`: every seed entry validates against the schema; classifier maps known ports to expected risks; unknown ports fall back correctly.
- `tests/test_scanner.py`: bind real listeners to ephemeral ports (port 0), assert the sweep finds them; assert closed ports read as closed; match patterns against recorded banner samples (SSH, HTTP) assert correct service and version extraction; nmap and KEV enrichment tested with mocked subprocess and cached fixtures.
- `tests/test_notifier.py`: mock `subprocess.run` and `ctypes`, assert correct per-platform delivery commands and emoji usage; assert fallbacks when channels are missing.
- Manual verification: open a listener on localhost, run `portpatrol scan`, confirm the console table, toast, and history record.

## Future Work (post-v1)

- `watch` mode: background daemon that rescans on an interval and notifies on new findings only.
- Multi-host mode: scan a CIDR range from a central machine.
- ML classifier behind the same knowledge base interface for risk scoring of unknown services.
- Scheduler generator: emits cron entries and a Windows Task Scheduler XML.
