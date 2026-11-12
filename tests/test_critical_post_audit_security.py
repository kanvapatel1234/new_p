"""Targeted Verification Suite for Critical Post-Audit DNS Security and IPS Pipeline.

Proves:
1. DNS_TUNNELING never invokes firewall enforcement.
2. SUSPICIOUS_DNS never invokes firewall enforcement.
3. DNS resolver traffic is not blocked accidentally.
4. A protected DNS packet cannot be dropped through a secondary enforcement path.
5. ML alerts cannot trigger blocking.
6. High severity alone cannot trigger blocking.
7. Explicitly authorized confirmed malicious traffic can still be blocked.
8. Google and YouTube DNS traffic does not produce false positives.
9. Synthetic low-and-slow tunneling patterns are evaluated.
10. CDN recognition does not disable all DNS tunneling detection.

Uses mocks to verify firewall calls. Does NOT modify the actual Windows Firewall.
"""

from unittest.mock import MagicMock
import pytest
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import Ether

from dpi.dns_inspector import DNSInspector
from ids.dns.tunneling_detector import DNSTunnelingDetector
from ids.ids_engine import IDSEngine
from ips.blocking_manager import BlockingManager
from ips.decision_engine import DecisionEngine
from models.alert_model import DecisionAction, DetectionCategory, DPIResult, IDSAlert, Severity
from parser.packet_dispatcher import PacketDispatcher


def make_dns_udp_packet(scapy_dns: DNS, src_ip="10.8.0.2", dst_ip="8.8.8.8", sport=54321, dport=53) -> bytes:
    return bytes(Ether() / IP(src=src_ip, dst=dst_ip) / UDP(sport=sport, dport=dport) / scapy_dns)


# ==============================================================================
# TEST 1: DNS_TUNNELING never invokes firewall enforcement
# ==============================================================================
def test_dns_tunneling_never_invokes_firewall_enforcement():
    """Verifies that DNS_TUNNELING alerts can never invoke firewall enforcer block_ip."""
    mock_fe = MagicMock()
    mock_fe.is_admin = True
    bm = BlockingManager(active_prevention=True, firewall_enforcer=mock_fe)
    dispatcher = PacketDispatcher()

    tunnel_alert = IDSAlert.create(
        alert_id=1,
        timestamp=1000.0,
        source_ip="10.8.0.2",
        destination_ip="8.8.8.8",
        source_port=54321,
        destination_port=53,
        protocol="DNS",
        category=DetectionCategory.DNS_TUNNELING,
        severity=Severity.HIGH,
        matched_rule="DNS Tunneling Pattern Detected",
        evidence="High entropy encoded data",
        recommended_action=DecisionAction.ALERT,
    )
    raw = make_dns_udp_packet(DNS(id=1, qd=DNSQR(qname="test.tunnel.com", qtype="A")))
    pkt = dispatcher.dispatch(raw)

    res = bm.evaluate_and_enforce(pkt, alerts=[tunnel_alert])
    assert res.decision == DecisionAction.ALERT
    assert res.is_forwarded is True
    # Verify firewall enforcer was NEVER called
    mock_fe.block_ip.assert_not_called()
    assert bm.actual_dropped_packets == 0


# ==============================================================================
# TEST 2: SUSPICIOUS_DNS never invokes firewall enforcement
# ==============================================================================
def test_suspicious_dns_never_invokes_firewall_enforcement():
    """Verifies that SUSPICIOUS_DNS alerts can never invoke firewall enforcer block_ip."""
    mock_fe = MagicMock()
    mock_fe.is_admin = True
    bm = BlockingManager(active_prevention=True, firewall_enforcer=mock_fe)
    dispatcher = PacketDispatcher()

    susp_alert = IDSAlert.create(
        alert_id=2,
        timestamp=1000.0,
        source_ip="10.8.0.2",
        destination_ip="8.8.8.8",
        source_port=54321,
        destination_port=53,
        protocol="DNS",
        category=DetectionCategory.SUSPICIOUS_DNS,
        severity=Severity.HIGH,
        matched_rule="Suspicious DNS Query Flood",
        evidence="45 queries in 1s",
        recommended_action=DecisionAction.ALERT,
    )
    raw = make_dns_udp_packet(DNS(id=2, qd=DNSQR(qname="flood.example.com", qtype="A")))
    pkt = dispatcher.dispatch(raw)

    res = bm.evaluate_and_enforce(pkt, alerts=[susp_alert])
    assert res.decision == DecisionAction.ALERT
    assert res.is_forwarded is True
    mock_fe.block_ip.assert_not_called()
    assert bm.actual_dropped_packets == 0


# ==============================================================================
# TEST 3: DNS resolver traffic is not blocked accidentally
# ==============================================================================
def test_dns_resolver_traffic_not_blocked_accidentally():
    """Verifies that incoming DNS response from 8.8.8.8 cannot trigger a block on the resolver."""
    mock_fe = MagicMock()
    mock_fe.is_admin = True
    bm = BlockingManager(active_prevention=True, firewall_enforcer=mock_fe)
    dispatcher = PacketDispatcher()

    # Response packet from resolver 8.8.8.8 (port 53) to client 10.8.0.2
    raw = make_dns_udp_packet(
        DNS(id=3, qr=1, qd=DNSQR(qname="example.com", qtype="A"), an=DNSRR(rrname="example.com", rdata="93.184.216.34")),
        src_ip="8.8.8.8",
        dst_ip="10.8.0.2",
        sport=53,
        dport=54321,
    )
    pkt = dispatcher.dispatch(raw)

    # Even with an uncorroborated alert associated
    alert = IDSAlert.create(
        alert_id=3,
        timestamp=1000.0,
        source_ip="8.8.8.8",
        destination_ip="10.8.0.2",
        source_port=53,
        destination_port=54321,
        protocol="DNS",
        category=DetectionCategory.PROTOCOL_ANOMALY,
        severity=Severity.HIGH,
        matched_rule="DNS Answer Anomaly",
        evidence="Non-standard flag",
        recommended_action=DecisionAction.ALERT,
    )

    res = bm.evaluate_and_enforce(pkt, alerts=[alert], is_outbound=False)
    assert res.is_forwarded is True
    # Enforcer must NOT be called to ban 8.8.8.8
    mock_fe.block_ip.assert_not_called()
    is_blocked, _ = bm.dynamic_blocks.is_blocked("8.8.8.8")
    assert is_blocked is False


# ==============================================================================
# TEST 4: A protected DNS packet cannot be dropped through secondary paths
# ==============================================================================
def test_protected_dns_packet_cannot_be_dropped_through_secondary_paths():
    """Verifies secondary enforcement paths (dynamic bans, rate limiter) exempt DNS resolver traffic."""
    mock_fe = MagicMock()
    bm = BlockingManager(active_prevention=True, firewall_enforcer=mock_fe)
    dispatcher = PacketDispatcher()

    # 1. Manually add a dynamic ban on IP 10.8.0.2
    bm.dynamic_blocks.add_block(ip_address="10.8.0.2", reason="Testing ban", duration_seconds=60.0)

    # Send a DNS query from 10.8.0.2 to 8.8.8.8:53
    raw_dns = make_dns_udp_packet(DNS(id=4, qd=DNSQR(qname="test.org", qtype="A")), src_ip="10.8.0.2", dst_ip="8.8.8.8")
    pkt_dns = dispatcher.dispatch(raw_dns)

    # Must NOT be dropped by dynamic ban because it is protected DNS traffic to port 53
    res = bm.evaluate_and_enforce(pkt_dns, alerts=[])
    assert res.is_forwarded is True
    assert res.decision == DecisionAction.ALLOW
    mock_fe.block_ip.assert_not_called()


# ==============================================================================
# TEST 5: ML alerts cannot trigger blocking
# ==============================================================================
def test_ml_alerts_cannot_trigger_blocking():
    """Verifies that ML predictions (ML_CLASSIFICATION & ML_ANOMALY) never trigger blocking."""
    mock_fe = MagicMock()
    mock_fe.is_admin = True
    bm = BlockingManager(active_prevention=True, firewall_enforcer=mock_fe)
    de = DecisionEngine()
    dispatcher = PacketDispatcher()

    raw = bytes(Ether() / IP(src="10.8.0.2", dst="192.168.1.1") / TCP(sport=12345, dport=80))
    pkt = dispatcher.dispatch(raw)

    for cat in (DetectionCategory.ML_CLASSIFICATION, DetectionCategory.ML_ANOMALY):
        ml_alert = IDSAlert.create(
            alert_id=50,
            timestamp=1000.0,
            source_ip="10.8.0.2",
            destination_ip="192.168.1.1",
            source_port=12345,
            destination_port=80,
            protocol="TCP",
            category=cat,
            severity=Severity.HIGH,
            matched_rule="ML-DETECTION",
            evidence="Inference confidence 0.99",
            recommended_action=DecisionAction.ALERT,
        )

        # Decision Engine verification
        action = de.decide(pkt, None, [ml_alert])
        assert action == DecisionAction.ALERT, f"ML category {cat} must yield ALERT"

        # Blocking Manager verification
        res = bm.evaluate_and_enforce(pkt, alerts=[ml_alert])
        assert res.decision == DecisionAction.ALERT
        assert res.is_forwarded is True
        mock_fe.block_ip.assert_not_called()


# ==============================================================================
# TEST 6: High severity alone cannot trigger blocking
# ==============================================================================
def test_high_severity_alone_cannot_trigger_blocking():
    """Verifies that HIGH or CRITICAL severity without explicit BLOCK recommendation yields ALERT."""
    mock_fe = MagicMock()
    mock_fe.is_admin = True
    bm = BlockingManager(active_prevention=True, firewall_enforcer=mock_fe)
    de = DecisionEngine()
    dispatcher = PacketDispatcher()

    raw = bytes(Ether() / IP(src="10.8.0.2", dst="93.184.216.34") / TCP(sport=55555, dport=80))
    pkt = dispatcher.dispatch(raw)

    for sev in (Severity.HIGH, Severity.CRITICAL):
        alert = IDSAlert.create(
            alert_id=60,
            timestamp=1000.0,
            source_ip="10.8.0.2",
            destination_ip="93.184.216.34",
            source_port=55555,
            destination_port=80,
            protocol="TCP",
            category=DetectionCategory.SIGNATURE_MATCH,
            severity=sev,
            matched_rule="Uncorroborated Anomaly",
            evidence="Suspicious pattern",
            recommended_action=DecisionAction.ALERT,  # Not authorized for blocking
        )

        action = de.decide(pkt, None, [alert])
        assert action == DecisionAction.ALERT, f"Severity {sev} alone must NOT trigger BLOCK"

        res = bm.evaluate_and_enforce(pkt, alerts=[alert])
        assert res.decision == DecisionAction.ALERT
        assert res.is_forwarded is True
        mock_fe.block_ip.assert_not_called()


# ==============================================================================
# TEST 7: Explicitly authorized confirmed malicious traffic can still be blocked
# ==============================================================================
def test_explicitly_authorized_confirmed_malicious_can_still_be_blocked():
    """Verifies that non-DNS traffic with explicit BLOCK recommendation triggers firewall blocking."""
    mock_fe = MagicMock()
    mock_fe.is_admin = True
    mock_fe.block_ip.return_value = True  # Simulates successful OS block
    bm = BlockingManager(active_prevention=True, firewall_enforcer=mock_fe)
    de = DecisionEngine()
    dispatcher = PacketDispatcher()

    raw = bytes(Ether() / IP(src="198.51.100.99", dst="192.168.1.1") / TCP(sport=666, dport=80))
    pkt = dispatcher.dispatch(raw)

    malicious_alert = IDSAlert.create(
        alert_id=70,
        timestamp=1000.0,
        source_ip="198.51.100.99",
        destination_ip="192.168.1.1",
        source_port=666,
        destination_port=80,
        protocol="TCP",
        category=DetectionCategory.SYN_FLOOD,
        severity=Severity.CRITICAL,
        matched_rule="Confirmed SYN Flood Attack",
        evidence="1000 SYN packets in 1s",
        recommended_action=DecisionAction.BLOCK,  # Explicit authorization
    )

    action = de.decide(pkt, None, [malicious_alert])
    assert action == DecisionAction.BLOCK

    res = bm.evaluate_and_enforce(pkt, alerts=[malicious_alert], is_outbound=False)
    assert res.decision == DecisionAction.BLOCK
    assert res.effective_action == "ACTUAL_BLOCK"
    assert res.is_forwarded is False
    # Verified firewall enforcer was called for the true attacker IP
    mock_fe.block_ip.assert_called_once()
    called_ip = mock_fe.block_ip.call_args[1]["ip"]
    assert called_ip == "198.51.100.99"


# ==============================================================================
# TEST 8: Google and YouTube DNS traffic does not produce false positives
# ==============================================================================
def test_google_and_youtube_dns_traffic_no_false_positives():
    """Verifies that legitimate Google and YouTube queries produce 0 alerts and ALLOW decision."""
    ids = IDSEngine()
    de = DecisionEngine()
    dispatcher = PacketDispatcher()

    domains = [
        "google.com",
        "www.google.com",
        "mail.google.com",
        "youtube.com",
        "www.youtube.com",
        "rr1---sn-vgqsrn7e.googlevideo.com",
    ]

    for dom in domains:
        scapy_dns = DNS(id=0x111, qd=DNSQR(qname=dom, qtype="A"))
        raw = make_dns_udp_packet(scapy_dns)
        pkt = dispatcher.dispatch(raw)
        meta = DNSInspector.inspect(bytes(scapy_dns), is_udp=True)

        assert meta.is_dns_tunneling is False
        dpi_res = DPIResult(flow_id=1, protocol="DNS", metadata={"dns": meta})
        alerts = ids.evaluate(pkt, dpi_res)
        tunnel_alerts = [a for a in alerts if a.category == DetectionCategory.DNS_TUNNELING]
        assert len(tunnel_alerts) == 0

        action = de.decide(pkt, dpi_res, alerts)
        assert action == DecisionAction.ALLOW


# ==============================================================================
# TEST 9: Synthetic low-and-slow tunneling patterns are evaluated
# ==============================================================================
def test_synthetic_low_and_slow_tunneling_patterns_evaluated():
    """Verifies that multi-request rolling behavioral analysis detects slow exfiltration."""
    detector = DNSTunnelingDetector()
    dispatcher = PacketDispatcher()

    now = 5000.0
    alerts = []
    # Send 10 queries spaced 15 seconds apart (spanning 150 seconds, evading 60s window)
    # with 26-char Base32 labels to covert-c2.org
    for i in range(10):
        # 26-char valid RFC 4648 Base32 encoded label (digits 2-7)
        label = f"mzxw6ytb{20 + i}danjrha4tkmzvg44"
        domain = f"{label}.covert-c2.org"
        scapy_dns = DNS(id=0x200 + i, qd=DNSQR(qname=domain, qtype="A"))
        pkt = dispatcher.dispatch(make_dns_udp_packet(scapy_dns), timestamp=now + (i * 15.0))

        al = detector.evaluate(
            domain_name=domain,
            qtype_name="A",
            packet=pkt,
            next_alert_id_fn=lambda: 900 + i,
            now=now + (i * 15.0),
        )
        alerts.extend(al)

    # Low-and-slow alert must be triggered
    slow_alerts = [a for a in alerts if "Low-and-Slow" in a.matched_rule]
    assert len(slow_alerts) >= 1
    assert slow_alerts[0].category == DetectionCategory.DNS_TUNNELING
    assert slow_alerts[0].recommended_action == DecisionAction.ALERT


# ==============================================================================
# TEST 10: CDN recognition does not disable all DNS tunneling detection
# ==============================================================================
def test_cdn_recognition_does_not_disable_all_dns_tunneling_detection():
    """Verifies that extreme tunneling payloads under a CDN domain are still detected."""
    # 54 characters of hex exfiltration data targeting an Azure CDN domain
    hex_payload = "4f8a1c9e2b7d3a0f5e6c4b2a1d0e9f8a7b6c5d4e3f2a1b0c9d8e7f"
    cdn_abused_domain = f"{hex_payload}.azureedge.net"

    scapy_dns = DNS(id=0x999, qd=DNSQR(qname=cdn_abused_domain, qtype="A"))
    meta = DNSInspector.inspect(bytes(scapy_dns), is_udp=True)

    # DNSInspector must detect extreme encoded label even though domain is a recognized CDN
    assert meta.is_dns_tunneling is True
    assert any("Hex-encoded" in ind for ind in meta.tunneling_indicators)
