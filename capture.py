"""Offline DNS anomaly demo, PCAP reader, and opt-in authorized live capture."""

import argparse
from datetime import datetime, timezone
from pathlib import Path
import ipaddress
import json
import logging
from config import BASE_DIR, DEFAULT_DATABASE, TYPE_NAMES
from detect import analyze_domain, load_popular_domains
from mitigation import SandboxHosts
from storage import EventStore

logger = logging.getLogger(__name__)


def packet_query(packet):
    from scapy.layers.dns import DNS, DNSQR
    from scapy.layers.inet import IP, UDP
    from scapy.layers.inet6 import IPv6

    if (
        not packet.haslayer(UDP)
        or int(packet[UDP].dport) != 53
        or not packet.haslayer(DNS)
        or not packet.haslayer(DNSQR)
        or packet[DNS].qr != 0
    ):
        return None
    if packet.haslayer(IP):
        source = packet[IP].src
    elif packet.haslayer(IPv6):
        source = packet[IPv6].src
    else:
        return None
    qname = packet[DNSQR].qname
    from rules import normalize_domain

    domain = normalize_domain(qname)
    if domain.endswith((".in-addr.arpa", ".ip6.arpa")):
        return None
    return {
        "domain": domain,
        "source_ip": source,
        "qtype": TYPE_NAMES.get(int(packet[DNSQR].qtype), "OTHER"),
    }


def process_query(
    query,
    store,
    popular_domains=frozenset(),
    legacy_popularity_escalation=False,
    sandbox=None,
):
    source_ip = str(ipaddress.ip_address(query["source_ip"]))
    event = analyze_domain(
        query["domain"],
        query.get("qtype", "A"),
        popular_domains,
        legacy_popularity_escalation,
    )
    event.update(
        timestamp=datetime.now(timezone.utc).isoformat(timespec="seconds"),
        source_ip=source_ip,
        action="observe-only",
    )
    if sandbox and event["verdict"] == "HIGH RISK":
        try:
            sandbox.add(event["domain"])
            event["action"] = "sandbox-preview-only"
        except (OSError, ValueError) as error:
            logger.warning("Sandbox preview skipped: %s", type(error).__name__)
            event["action"] = "sandbox-preview-failed"
    store.append(event)
    return event


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument(
        "--demo",
        action="store_true",
        help="Read supplied synthetic queries; send no traffic",
    )
    mode.add_argument(
        "--pcap", type=Path, help="Read an authorized local PCAP/PCAPNG file"
    )
    mode.add_argument(
        "--live", action="store_true", help="Capture UDP DNS on an authorized interface"
    )
    parser.add_argument(
        "--interface", help="Required for live capture; list adapters with Scapy"
    )
    parser.add_argument("--database", type=Path, default=DEFAULT_DATABASE)
    parser.add_argument("--max-events", type=int, default=1000)
    parser.add_argument(
        "--popular-domains",
        type=Path,
        help="Optional explicit suffix list; no automatic downloads",
    )
    parser.add_argument(
        "--legacy-popularity-escalation",
        action="store_true",
        help="Reproduce the original popular-name >=50 escalation; may increase false positives",
    )
    parser.add_argument(
        "--sandbox-hosts",
        type=Path,
        help="Opt-in directory for hosts.preview; does not block traffic",
    )
    args = parser.parse_args()
    if args.live and not args.interface:
        parser.error("--live requires --interface")
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
    store = EventStore(args.database, args.max_events)
    popular = load_popular_domains(args.popular_domains)
    sandbox = SandboxHosts(args.sandbox_hosts) if args.sandbox_hosts else None
    counts = {"processed": 0, "skipped": 0}

    def accept(query):
        event = process_query(
            query, store, popular, args.legacy_popularity_escalation, sandbox
        )
        counts["processed"] += 1
        print(json.dumps(event, ensure_ascii=True))

    def handle(packet):
        try:
            query = packet_query(packet)
            if query is not None:
                accept(query)
        except (UnicodeError, ValueError, IndexError, KeyError, AttributeError):
            counts["skipped"] += 1
            logger.warning("Skipped malformed or unsupported DNS packet")

    if args.demo:
        queries = json.loads(
            (BASE_DIR / "examples" / "synthetic-queries.json").read_text(
                encoding="utf-8"
            )
        )
        for query in queries:
            accept(query)
    else:
        from scapy.all import sniff

        if args.pcap:
            sniff(offline=str(args.pcap), prn=handle, store=False)
        else:
            logger.info(
                "Live capture enabled on the selected interface. No system blocking is performed."
            )
            sniff(
                iface=args.interface, filter="udp dst port 53", prn=handle, store=False
            )
    print(json.dumps({"summary": counts}))


if __name__ == "__main__":
    main()
