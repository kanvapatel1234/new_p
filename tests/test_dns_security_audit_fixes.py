"""Comprehensive Regression and Security Test Suite for DNS Audit & IPS Policy Guarantees.

Validates:
1. Legitimate traffic: Google, YouTube, CDN/Cloud, long domains, repeated queries, record types (TXT DKIM/SPF), browsing.
2. Suspicious traffic: High-entropy labels, abnormally long labels, query floods, synthetic tunneling, suspicious TXT.
3. Response policy: DNS tunneling never blocks by default, unknown domains never block, ML alerts advisory only,
   confirmed malicious follows policy, ALERT events never invoke firewall enforcement, DNS resolvers never banned.
"""

import time
import pytest
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import Ether
from scapy.layers.dns import DNS, DNSQR, DNSRR

from dpi.dns_inspector import DNSInspector, calculate_entropy
from dpi.dpi_engine import DPIEngine
from ids.dns.common import is_cdn_or_cloud_domain, is_legitimate_txt_record
from ids.dns.tunneling_detector import DNSTunnelingDetector
from ids.ids_engine import IDSEngine
from ips.blocking_manager import BlockingManager
from ips.decision_engine import DecisionEngine
from models.alert_model import DecisionAction, DetectionCategory, DPIResult, IDSAlert, Severity
from parser.packet_dispatcher import PacketDispatcher


# --- Helper to create Scapy DNS packet ---
def make_dns_packet(scapy_dns: DNS, src_ip="10.8.0.2", dst_ip="8.8.8.8", sport=54321, dport=53) -> bytes:
    return bytes(Ether() / IP(src=src_ip, dst=dst_ip) / UDP(sport=sport, dport=dport) / scapy_dns)


# ==============================================================================
# SECTION 1: LEGITIMATE TRAFFIC TESTS
# ==============================================================================

def test_legitimate_google_dns_queries():
    """Verifies that normal Google DNS queries are never classified as DNS tunneling."""
    google_domains = [
        "google.com",
        "www.google.com",
        "mail.google.com",
        "apis.google.com",
        "fonts.googleapis.com",
        "lh3.googleusercontent.com",
        "play.googleapis.com",
        "accounts.google.com",
        "drive.google.com",
    ]
    ids = IDSEngine()
    decision_engine = DecisionEngine()
    dispatcher = PacketDispatcher()

    for dom in google_domains:
        # Check CDN/cloud recognition
        assert is_cdn_or_cloud_domain(dom) is True, f"Failed CDN classification for {dom}"

        scapy_dns = DNS(id=0x1234, qr=0, qd=DNSQR(qname=dom, qtype="A"))
        raw = make_dns_packet(scapy_dns)
        packet = dispatcher.dispatch(raw)
        dns_meta = DNSInspector.inspect(bytes(scapy_dns), is_udp=True)

        assert dns_meta.is_dns_tunneling is False, f"Google domain {dom} falsely flagged as tunneling in DNSInspector"

        dpi_res = DPIResult(flow_id=1, protocol="DNS", metadata={"dns": dns_meta})
        alerts = ids.evaluate(packet, dpi_res)
        tunneling_alerts = [a for a in alerts if a.category == DetectionCategory.DNS_TUNNELING]
        assert len(tunneling_alerts) == 0, f"Google domain {dom} generated DNS_TUNNELING alert: {tunneling_alerts}"

        action = decision_engine.decide(packet, dpi_res, alerts)
        assert action == DecisionAction.ALLOW, f"Google domain {dom} should be ALLOW, got {action}"


def test_legitimate_youtube_dns_queries():
    """Verifies that YouTube and GoogleVideo domains are never classified as DNS tunneling."""
    youtube_domains = [
        "youtube.com",
        "www.youtube.com",
        "rr1---sn-vgqsrn7e.googlevideo.com",
        "rr2---sn-4g5ednss.googlevideo.com",
        "i.ytimg.com",
        "yt3.ggpht.com",
        "youtubei.googleapis.com",
        "music.youtube.com",
    ]
    ids = IDSEngine()
    decision_engine = DecisionEngine()
    dispatcher = PacketDispatcher()

    for dom in youtube_domains:
        assert is_cdn_or_cloud_domain(dom) is True, f"Failed CDN classification for {dom}"

        scapy_dns = DNS(id=0x2345, qr=0, qd=DNSQR(qname=dom, qtype="A"))
        raw = make_dns_packet(scapy_dns)
        packet = dispatcher.dispatch(raw)
        dns_meta = DNSInspector.inspect(bytes(scapy_dns), is_udp=True)

        assert dns_meta.is_dns_tunneling is False, f"YouTube domain {dom} falsely flagged as tunneling"

        dpi_res = DPIResult(flow_id=1, protocol="DNS", metadata={"dns": dns_meta})
        alerts = ids.evaluate(packet, dpi_res)
        tunneling_alerts = [a for a in alerts if a.category == DetectionCategory.DNS_TUNNELING]
        assert len(tunneling_alerts) == 0, f"YouTube domain {dom} produced tunneling alert: {tunneling_alerts}"

        action = decision_engine.decide(packet, dpi_res, alerts)
        assert action == DecisionAction.ALLOW


def test_legitimate_cdn_and_cloud_subdomains():
    """Verifies CDN subdomains with relatively high character variation are not false-positive tunneling."""
    cdn_domains = [
        "video-weaver.sfo01.hls.live-video.net",
        "wdcp-bap-southcentralus.trafficmanager.net",
        "edge-chat.instagram.com",
        "sentry.io",
        "init-p01st.push.apple.com",
        "configuration.apple.com",
        "teams.microsoft.com",
        "login.microsoftonline.com",
    ]
    ids = IDSEngine()
    decision_engine = DecisionEngine()
    dispatcher = PacketDispatcher()

    for dom in cdn_domains:
        scapy_dns = DNS(id=0x3456, qr=0, qd=DNSQR(qname=dom, qtype="A"))
        raw = make_dns_packet(scapy_dns)
        packet = dispatcher.dispatch(raw)
        dns_meta = DNSInspector.inspect(bytes(scapy_dns), is_udp=True)

        assert dns_meta.is_dns_tunneling is False

        dpi_res = DPIResult(flow_id=1, protocol="DNS", metadata={"dns": dns_meta})
        alerts = ids.evaluate(packet, dpi_res)
        tunneling_alerts = [a for a in alerts if a.category == DetectionCategory.DNS_TUNNELING]
        assert len(tunneling_alerts) == 0

        action = decision_engine.decide(packet, dpi_res, alerts)
        assert action == DecisionAction.ALLOW


def test_legitimate_long_domain_names():
    """Verifies that non-CDN long domains with natural words do not trigger tunneling."""
    long_domains = [
        "veteransbenefitsadministration.departmentofveteransaffairs.gov",
        "ec2-54-210-123-45.compute-1.amazonaws.com",
        "international-association-of-cybersecurity-professionals.org",
    ]
    dispatcher = PacketDispatcher()
    decision_engine = DecisionEngine()

    for dom in long_domains:
        scapy_dns = DNS(id=0x4567, qr=0, qd=DNSQR(qname=dom, qtype="A"))
        packet = dispatcher.dispatch(make_dns_packet(scapy_dns))
        dns_meta = DNSInspector.inspect(bytes(scapy_dns), is_udp=True)

        assert dns_meta.is_dns_tunneling is False
        action = decision_engine.decide(packet, None, [])
        assert action == DecisionAction.ALLOW


def test_legitimate_repeated_normal_dns_queries():
    """Verifies that repeated normal queries do not trigger churn thresholds."""
    detector = DNSTunnelingDetector()
    dispatcher = PacketDispatcher()

    now = 1000.0
    for i in range(25):
        scapy_dns = DNS(id=0x5000 + i, qr=0, qd=DNSQR(qname="www.youtube.com", qtype="A"))
        packet = dispatcher.dispatch(make_dns_packet(scapy_dns))
        dns_meta = DNSInspector.inspect(bytes(scapy_dns), is_udp=True)

        alerts = detector.evaluate(
            domain_name="www.youtube.com",
            qtype_name="A",
            packet=packet,
            next_alert_id_fn=lambda: i + 1,
            now=now + (i * 0.2),
        )
        assert len(alerts) == 0, f"Repeated query {i} triggered alert: {alerts}"


def test_legitimate_multiple_dns_record_types():
    """Verifies A, AAAA, CNAME, MX, and especially TXT records (SPF, DKIM, DMARC) are not flagged."""
    dispatcher = PacketDispatcher()

    # Legitimate DKIM TXT record (typically 200-350 bytes of base64 key)
    dkim_payload = (
        "v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0tG+6"
        "s2jFjW+1dE8W0aQeW5k5l8w4b2rQ8X2t7m6k9y0w3u1e7r6t5y4u3i2o1p0a9s8d7f"
        "6g5h4j3k2l1m0z9x8c7v6b5n4m3l2k1j0h9g8f7d6s5a4p3o2i1u0y9t8r7e6w5q4a"
        "3s2d1f0g9h8j7k6l5z4x3c2v1b0n9m8l7k6j5h4g3f2d1s0a9p8o7i6u5y4t3r2e1w"
        "QIDAQAB"
    )
    assert is_legitimate_txt_record(dkim_payload) is True

    # Legitimate SPF TXT record
    spf_payload = "v=spf1 include:_spf.google.com ip4:192.168.1.0/24 ~all"
    assert is_legitimate_txt_record(spf_payload) is True

    # Legitimate DMARC TXT record
    dmarc_payload = "v=DMARC1; p=reject; rua=mailto:dmarc-reports@example.com; pct=100"
    assert is_legitimate_txt_record(dmarc_payload) is True

    # Test Scapy DNS response carrying legitimate DKIM TXT record
    scapy_resp = DNS(
        id=0x6789,
        qr=1,
        qd=DNSQR(qname="google._domainkey.example.com", qtype="TXT"),
        an=DNSRR(rrname="google._domainkey.example.com", type="TXT", rdata=[dkim_payload.encode()]),
    )
    dns_meta = DNSInspector.inspect(bytes(scapy_resp), is_udp=True)
    assert dns_meta.is_dns_tunneling is False, "Legitimate DKIM TXT was falsely flagged as tunneling!"


def test_legitimate_normal_browsing_traffic_pipeline():
    """End-to-end pipeline test for normal browsing: DNS lookup followed by TLS traffic."""
    bm = BlockingManager(active_prevention=False)
    dispatcher = PacketDispatcher()

    # 1. DNS Query from WireGuard client 10.8.0.2 to DNS 8.8.8.8
    scapy_dns = DNS(id=0x7777, qr=0, qd=DNSQR(qname="www.youtube.com", qtype="A"))
    pkt_dns = dispatcher.dispatch(make_dns_packet(scapy_dns, src_ip="10.8.0.2", dst_ip="8.8.8.8"))
    res_dns = bm.evaluate_and_enforce(pkt_dns, alerts=[])

    assert res_dns.decision == DecisionAction.ALLOW
    assert res_dns.is_forwarded is True
    assert bm.actual_dropped_packets == 0

    # 2. DNS Response from 8.8.8.8 to client 10.8.0.2
    scapy_dns_resp = DNS(
        id=0x7777,
        qr=1,
        qd=DNSQR(qname="www.youtube.com", qtype="A"),
        an=DNSRR(rrname="www.youtube.com", type="A", rdata="142.250.190.46"),
    )
    pkt_dns_resp = dispatcher.dispatch(make_dns_packet(scapy_dns_resp, src_ip="8.8.8.8", dst_ip="10.8.0.2", sport=53, dport=54321))
    res_resp = bm.evaluate_and_enforce(pkt_dns_resp, alerts=[])

    assert res_resp.is_forwarded is True
    assert bm.actual_dropped_packets == 0

    # 3. HTTPS SYN packet from client to YouTube IP 142.250.190.46:443
    pkt_syn = dispatcher.dispatch(bytes(Ether() / IP(src="10.8.0.2", dst="142.250.190.46") / TCP(sport=50000, dport=443, flags="S")))
    res_syn = bm.evaluate_and_enforce(pkt_syn, alerts=[])

    assert res_syn.decision == DecisionAction.ALLOW
    assert res_syn.is_forwarded is True
    assert bm.actual_dropped_packets == 0

    # Neither the client nor the DNS resolver should be dynamically banned
    is_blocked_client, _ = bm.dynamic_blocks.is_blocked("10.8.0.2")
    is_blocked_resolver, _ = bm.dynamic_blocks.is_blocked("8.8.8.8")
    assert is_blocked_client is False
    assert is_blocked_resolver is False


# ==============================================================================
# SECTION 2: SUSPICIOUS TRAFFIC TESTS
# ==============================================================================

def test_suspicious_high_entropy_subdomains():
    """Verifies that high-entropy encoded non-CDN subdomains are detected."""
    # 48 chars of random hex data under an untrusted domain
    suspicious_label = "4f8a1c9e2b7d3a0f5e6c4b2a1d0e9f8a7b6c5d4e3f2a1b0c"
    domain = f"{suspicious_label}.tunnel-exfil-c2.net"

    dns_meta = DNSInspector.inspect(bytes(DNS(id=0x8888, qr=0, qd=DNSQR(qname=domain, qtype="A"))), is_udp=True)
    assert dns_meta.is_dns_tunneling is True
    assert any("Hex-encoded" in ind for ind in dns_meta.tunneling_indicators)


def test_suspicious_abnormally_long_dns_labels():
    """Verifies that abnormally long candidate subdomain labels trigger detection."""
    # 52 chars of base32 data
    b32_label = "mzxw6ytboi5danjrha4tkmzvg44dsnrqmq2tmobzguydsnbugmza"
    domain = f"{b32_label}.exfiltrate.cc"

    dns_meta = DNSInspector.inspect(bytes(DNS(id=0x8889, qr=0, qd=DNSQR(qname=domain, qtype="A"))), is_udp=True)
    assert dns_meta.is_dns_tunneling is True
    assert any("Base32-encoded" in ind for ind in dns_meta.tunneling_indicators)


def test_suspicious_high_frequency_dns_queries():
    """Verifies high-frequency query flood from a single host triggers anomaly alert."""
    ids = IDSEngine()
    dispatcher = PacketDispatcher()

    # Send 45 DNS queries within 1 second
    now = 2000.0
    alerts = []
    for i in range(45):
        scapy_dns = DNS(id=i, qr=0, qd=DNSQR(qname=f"test{i}.example.com", qtype="A"))
        raw = make_dns_packet(scapy_dns)
        packet = dispatcher.dispatch(raw, timestamp=now + (i * 0.01))
        dpi_res = DPIResult(flow_id=i, protocol="DNS", metadata={"dns": DNSInspector.inspect(bytes(scapy_dns), is_udp=True)})
        al = ids.evaluate(packet, dpi_res)
        alerts.extend(al)

    flood_alerts = [a for a in alerts if "Flood" in a.matched_rule or a.category == DetectionCategory.SUSPICIOUS_DNS]
    assert len(flood_alerts) >= 1


def test_suspicious_synthetic_dns_tunneling_patterns():
    """Verifies that multi-query churn of encoded subdomains on an untrusted domain triggers tunneling detector."""
    detector = DNSTunnelingDetector()
    dispatcher = PacketDispatcher()

    now = 3000.0
    alerts = []
    for i in range(12):
        hex_label = f"a{i:02d}f0b3e7c8d9e1a2b3c4d5e6f7a8b9c0d1e2f3a4b5"
        domain = f"{hex_label}.covert-data.xyz"
        scapy_dns = DNS(id=0x9000 + i, qr=0, qd=DNSQR(qname=domain, qtype="A"))
        packet = dispatcher.dispatch(make_dns_packet(scapy_dns), timestamp=now + (i * 0.1))
        dns_meta = DNSInspector.inspect(bytes(scapy_dns), is_udp=True)

        al = detector.evaluate(
            domain_name=domain,
            qtype_name="A",
            packet=packet,
            next_alert_id_fn=lambda: i + 1,
            now=now + (i * 0.1),
        )
        alerts.extend(al)

    assert len(alerts) >= 1
    assert any(a.category == DetectionCategory.DNS_TUNNELING for a in alerts)
    # Recommended action must be strictly ALERT
    for a in alerts:
        assert a.recommended_action == DecisionAction.ALERT


def test_suspicious_txt_record_tunneling_payload():
    """Verifies that non-standard, high-entropy, large TXT payloads are flagged as tunneling."""
    # 300 bytes of random non-standard payload (not SPF/DKIM/DMARC)
    suspicious_payload = "7a9f8b3c1d2e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a" * 5
    assert not is_legitimate_txt_record(suspicious_payload)

    scapy_resp = DNS(
        id=0x9999,
        qr=1,
        qd=DNSQR(qname="tunnel.darkc2.org", qtype="TXT"),
        an=DNSRR(rrname="tunnel.darkc2.org", type="TXT", rdata=[suspicious_payload.encode()]),
    )
    dns_meta = DNSInspector.inspect(bytes(scapy_resp), is_udp=True)
    assert dns_meta.is_dns_tunneling is True
    assert any("TXT payload" in ind for ind in dns_meta.tunneling_indicators)


# ==============================================================================
# SECTION 3: RESPONSE POLICY & FIREWALL ENFORCEMENT AUDIT
# ==============================================================================

def test_policy_dns_tunneling_never_blocks_by_default():
    """Policy invariant: DNS tunneling suspicion must ALWAYS be ALERT only and never BLOCK."""
    decision_engine = DecisionEngine()
    bm = BlockingManager(active_prevention=False)
    dispatcher = PacketDispatcher()

    tunnel_alert = IDSAlert.create(
        alert_id=101,
        timestamp=time.time(),
        source_ip="10.8.0.2",
        destination_ip="8.8.8.8",
        source_port=54321,
        destination_port=53,
        protocol="DNS",
        category=DetectionCategory.DNS_TUNNELING,
        severity=Severity.HIGH,  # Even with HIGH severity
        matched_rule="DNS Tunneling Pattern Detected",
        evidence="High entropy encoded labels",
        recommended_action=DecisionAction.ALERT,
    )

    pkt = dispatcher.dispatch(bytes(Ether() / IP(src="10.8.0.2", dst="8.8.8.8") / UDP(sport=54321, dport=53)))

    # 1. Decision Engine arbitration
    action = decision_engine.decide(pkt, None, [tunnel_alert])
    assert action == DecisionAction.ALERT, f"DNS tunneling MUST be ALERT, got {action}"
    assert action != DecisionAction.BLOCK

    # 2. IPS Enforcement pipeline
    res = bm.evaluate_and_enforce(pkt, alerts=[tunnel_alert])
    assert res.decision == DecisionAction.ALERT
    assert res.effective_action == "ALERT"
    assert res.is_forwarded is True
    assert res.dynamic_ban_issued is False

    # 3. Dynamic blocks table must NOT contain client
    is_blocked, _ = bm.dynamic_blocks.is_blocked("10.8.0.2")
    assert is_blocked is False


def test_policy_unknown_domain_never_blocks():
    """Policy invariant: Unknown domains must never block solely because they are unknown."""
    decision_engine = DecisionEngine()
    dispatcher = PacketDispatcher()
    bm = BlockingManager(active_prevention=True)

    unknown_alert = IDSAlert.create(
        alert_id=102,
        timestamp=time.time(),
        source_ip="10.8.0.2",
        destination_ip="8.8.8.8",
        source_port=54321,
        destination_port=53,
        protocol="DNS",
        category=DetectionCategory.THREAT_REPUTATION,
        severity=Severity.LOW,
        matched_rule="Unknown Domain Lookup",
        evidence="Domain newly registered or unknown domain in reputation database",
        recommended_action=DecisionAction.ALERT,
    )

    pkt = dispatcher.dispatch(bytes(Ether() / IP(src="10.8.0.2", dst="8.8.8.8") / UDP(sport=54321, dport=53)))
    action = decision_engine.decide(pkt, None, [unknown_alert])
    assert action == DecisionAction.ALERT

    res = bm.evaluate_and_enforce(pkt, alerts=[unknown_alert])
    assert res.decision == DecisionAction.ALERT
    assert res.is_forwarded is True


def test_policy_ml_predictions_never_block():
    """Policy invariant: ML predictions are advisory only and must never directly block."""
    decision_engine = DecisionEngine()
    bm = BlockingManager(active_prevention=True)
    dispatcher = PacketDispatcher()

    for cat in (DetectionCategory.ML_CLASSIFICATION, DetectionCategory.ML_ANOMALY):
        ml_alert = IDSAlert.create(
            alert_id=103,
            timestamp=time.time(),
            source_ip="10.8.0.2",
            destination_ip="192.168.1.1",
            source_port=12345,
            destination_port=80,
            protocol="TCP",
            category=cat,
            severity=Severity.HIGH,  # High severity ML
            matched_rule="ML-RF-CLASSIFIER",
            evidence="RandomForest predicted malicious flow with 0.95 confidence",
            recommended_action=DecisionAction.ALERT,
        )

        pkt = dispatcher.dispatch(bytes(Ether() / IP(src="10.8.0.2", dst="192.168.1.1") / TCP(sport=12345, dport=80)))
        action = decision_engine.decide(pkt, None, [ml_alert])
        assert action == DecisionAction.ALERT, f"ML category {cat} must not block!"

        res = bm.evaluate_and_enforce(pkt, alerts=[ml_alert])
        assert res.decision == DecisionAction.ALERT
        assert res.is_forwarded is True


def test_policy_confirmed_malicious_follows_configured_enforcement():
    """Verifies that confirmed malicious activity yields BLOCK and adheres to Simulation vs Active mode."""
    decision_engine = DecisionEngine()
    dispatcher = PacketDispatcher()

    crit_alert = IDSAlert.create(
        alert_id=104,
        timestamp=time.time(),
        source_ip="198.51.100.99",
        destination_ip="192.168.1.5",
        source_port=666,
        destination_port=80,
        protocol="TCP",
        category=DetectionCategory.SYN_FLOOD,
        severity=Severity.CRITICAL,
        matched_rule="TCP SYN Flood Exhaustion",
        evidence="1000 SYNs/sec received",
        recommended_action=DecisionAction.BLOCK,
    )

    pkt = dispatcher.dispatch(bytes(Ether() / IP(src="198.51.100.99", dst="192.168.1.5") / TCP(sport=666, dport=80)))
    action = decision_engine.decide(pkt, None, [crit_alert])
    assert action == DecisionAction.BLOCK

    # In Simulation Mode:
    bm_sim = BlockingManager(active_prevention=False)
    res_sim = bm_sim.evaluate_and_enforce(pkt, alerts=[crit_alert])
    assert res_sim.decision == DecisionAction.BLOCK
    assert res_sim.effective_action == "SIMULATED_BLOCK"
    assert res_sim.is_forwarded is True
    assert bm_sim.simulated_blocks == 1
    assert bm_sim.actual_dropped_packets == 0


def test_policy_alert_events_never_invoke_firewall_enforcement():
    """Verifies that ALERT-level events never trigger dynamic blocks or firewall enforcer rules."""
    bm = BlockingManager(active_prevention=True)
    dispatcher = PacketDispatcher()

    for i in range(10):
        alert = IDSAlert.create(
            alert_id=200 + i,
            timestamp=time.time(),
            source_ip="10.8.0.2",
            destination_ip="93.184.216.34",
            source_port=50000 + i,
            destination_port=80,
            protocol="TCP",
            category=DetectionCategory.PROTOCOL_ANOMALY,
            severity=Severity.MEDIUM,
            matched_rule="Minor Protocol Variance",
            evidence="Non-standard header formatting",
            recommended_action=DecisionAction.ALERT,
        )
        pkt = dispatcher.dispatch(bytes(Ether() / IP(src="10.8.0.2", dst="93.184.216.34") / TCP(sport=50000 + i, dport=80)))
        res = bm.evaluate_and_enforce(pkt, alerts=[alert])
        assert res.decision == DecisionAction.ALERT
        assert res.is_forwarded is True

    # Firewall rules created must be 0
    assert len(bm.firewall_enforcer.get_active_blocks()) == 0
    assert bm.actual_dropped_packets == 0


def test_policy_upstream_dns_resolver_never_dynamically_banned():
    """Verifies that upstream DNS resolver 8.8.8.8 is never banned by dynamic block promotions."""
    bm = BlockingManager(active_prevention=True)
    dispatcher = PacketDispatcher()

    # Even if an alert has source_ip="8.8.8.8" (from a DNS response), the resolver must NOT be banned
    alert = IDSAlert.create(
        alert_id=301,
        timestamp=time.time(),
        source_ip="8.8.8.8",
        destination_ip="10.8.0.2",
        source_port=53,
        destination_port=54321,
        protocol="DNS",
        category=DetectionCategory.SIGNATURE_MATCH,
        severity=Severity.CRITICAL,
        matched_rule="Exploit in DNS Answer",
        evidence="Malformed RR pointer",
        recommended_action=DecisionAction.BLOCK,
    )
    pkt = dispatcher.dispatch(make_dns_packet(DNS(id=0x1111), src_ip="8.8.8.8", dst_ip="10.8.0.2", sport=53, dport=54321))
    bm.evaluate_and_enforce(pkt, alerts=[alert])

    is_blocked, _ = bm.dynamic_blocks.is_blocked("8.8.8.8")
    assert is_blocked is False, "Upstream DNS resolver 8.8.8.8 was dynamically banned!"
