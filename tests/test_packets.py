from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import IP, UDP
from scapy.layers.inet6 import IPv6
from scapy.utils import wrpcap
from capture import packet_query, main
from storage import EventStore


def test_ipv4_ipv6_queries_and_responses():
    query = DNS(qd=DNSQR(qname="www.example.test"))
    assert (
        packet_query(IP(src="192.0.2.1") / UDP(dport=53) / query)["source_ip"]
        == "192.0.2.1"
    )
    assert (
        packet_query(IPv6(src="2001:db8::1") / UDP(dport=53) / query)["source_ip"]
        == "2001:db8::1"
    )
    assert (
        packet_query(IP() / UDP(dport=53) / DNS(qr=1, qd=DNSQR(qname="example.test")))
        is None
    )
    assert packet_query(IP() / UDP(dport=5353) / query) is None
    assert packet_query(UDP(dport=53) / query) is None


def test_reverse_queries_ignored():
    packet = IP() / UDP(dport=53) / DNS(qd=DNSQR(qname="1.2.0.192.in-addr.arpa"))
    assert packet_query(packet) is None


def test_offline_pcap_skips_bad_names_without_sending_packets(
    tmp_path, monkeypatch, capsys
):
    packets = [
        IP(src="192.0.2.1") / UDP(dport=53) / DNS(qd=DNSQR(qname="www.example.test")),
        IP(src="192.0.2.1") / UDP(dport=53) / DNS(qd=DNSQR(qname=b"\xff.test")),
    ]
    pcap = tmp_path / "synthetic.pcap"
    database = tmp_path / "events.sqlite3"
    wrpcap(str(pcap), packets)
    monkeypatch.setattr(
        "sys.argv", ["capture.py", "--pcap", str(pcap), "--database", str(database)]
    )
    main()
    assert EventStore(database).snapshot()[1]["total"] == 1
    assert '"skipped": 1' in capsys.readouterr().out
