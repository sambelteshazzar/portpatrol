"""Command line interface: scan and explain commands."""

from __future__ import annotations

import argparse
import sys
from datetime import datetime, timezone
from pathlib import Path

from portpatrol import knowledge, scanner
from portpatrol.defaults import TOP_PORTS
from portpatrol.notifier import notify, summary_message
from portpatrol.report import append_history, console_table, to_json

HISTORY_PATH = Path.home() / ".portpatrol" / "history.json"


def build_parser():
    parser = argparse.ArgumentParser(
        prog="portpatrol",
        description="Scan this machine for open ports and classify the risk.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="scan localhost and report open ports")
    scan.add_argument("--ports", default="top1000",
                      help="top50 | top100 | top1000 | all | 80,443 | 8000-8100")
    scan.add_argument("--json", action="store_true", help="machine-readable output on stdout")
    scan.add_argument("--kev", action="store_true", help="cross-reference CISA KEV catalog")
    scan.add_argument("--no-notify", action="store_true", help="suppress desktop notifications")
    scan.add_argument("--verbose", action="store_true", help="log skipped enrichments and probe failures")
    scan.set_defaults(func=cmd_scan)

    explain = sub.add_parser("explain", help="print the knowledge base entry for a port")
    explain.add_argument("port", type=int)
    explain.set_defaults(func=cmd_explain)
    return parser


def cmd_scan(args):
    try:
        ports = knowledge.parse_port_spec(args.ports, TOP_PORTS)
    except ValueError as exc:
        print(f"portpatrol: {exc}", file=sys.stderr)
        return 2

    kb = knowledge.load_knowledge_base()
    svc_index = knowledge.service_index(kb)

    open_ports = scanner.sweep(ports)
    if args.verbose:
        print(f"portpatrol: {len(open_ports)} open of {len(ports)} scanned", file=sys.stderr)

    findings = [scanner.identify(p, knowledge.get_entry(kb, p), svc_index) for p in open_ports]

    services = scanner.enrich_with_nmap(open_ports)
    if args.verbose and open_ports and not services:
        print("portpatrol: nmap not found; socket probes only", file=sys.stderr)
    for f in findings:
        extra = services.get(f["port"]) or {}
        if f["service"] in (None, "unknown") and extra.get("service"):
            f["service"] = extra["service"]
        if extra.get("version") and not f["version"]:
            f["version"] = extra["version"]
        if extra.get("product"):
            f["product"] = extra["product"]

    for f in findings:
        service = f["service"] if f["service"] not in (None, "unknown") else None
        f["risk"] = knowledge.classify_port(kb, f["port"], service)
        f["cves"] = []

    if args.kev:
        scanner.enrich_with_kev(findings, kb, Path.home() / ".portpatrol" / "kev.json")

    result = {
        "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "target": "127.0.0.1",
        "scanned": len(ports),
        "open": findings,
    }

    if args.json:
        print(to_json(result))
    else:
        print(console_table(findings))

    if not args.no_notify:
        notify("PortPatrol", summary_message(findings))
        for f in findings:
            if f["risk"] != "critical":
                continue
            detail = f.get("service") or "unknown service"
            cves = ", ".join(f.get("cves", []))
            suffix = f" ({cves})" if cves else ""
            notify(
                f"🚨 Port {f['port']} {detail}",
                f"Critical: open and exploitable{suffix}. Run 'portpatrol explain {f['port']}'.",
            )

    append_history(result, HISTORY_PATH)
    return 1 if findings else 0


def cmd_explain(args):
    kb = knowledge.load_knowledge_base()
    entry = knowledge.get_entry(kb, args.port)
    if entry is None:
        print(f"No knowledge base entry for port {args.port}.")
        print("Risk: unknown — not a well-known port. Verify manually what listens on it.")
        return 0
    print(f"Port {entry['port']}/tcp — {entry['service']} — risk: {entry['risk']}")
    print(f"Advice: {entry['advice']}")
    if entry.get("kev_hints"):
        print("KEV hints: " + ", ".join(entry["kev_hints"]))
    return 0


def main(argv=None):
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except KeyboardInterrupt:
        return 2
