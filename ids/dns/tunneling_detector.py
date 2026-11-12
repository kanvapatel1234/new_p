"""DNS Tunneling and Data Exfiltration Detector.

Combines structural length, encoded character sets, unique subdomain churn per apex domain,
and aggregated query volume. Robustly exempts legitimate SPF/DKIM/DMARC TXT records.
Implements separate composite tunneling and dedicated high-churn detection paths.
"""

from __future__ import annotations

import logging
import time
from collections import defaultdict, deque
from typing import Dict, List, Optional, Set, Tuple

from ids.dns.common import (
    BASE32_REGEX,
    BASE64_SUBDOMAIN_REGEX,
    HEX_REGEX,
    calculate_entropy,
    extract_apex_and_subdomain,
    get_packet_endpoints,
    is_cdn_or_cloud_domain,
    is_legitimate_txt_record,
)
from models.alert_model import DecisionAction, DetectionCategory, IDSAlert, Severity
from models.packet_models import ParsedPacket

logger = logging.getLogger(__name__)


class DNSTunnelingDetector:
    """Detects covert DNS tunneling channels using multi-vector structural and behavioral analysis."""

    def __init__(self, max_apex_tracked: int = 1000, window_seconds: float = 60.0) -> None:
        self.max_apex_tracked = max_apex_tracked
        self.window_seconds = window_seconds

        # State tracking: (client_ip, apex_domain) -> deque of (timestamp, query_name, query_bytes)
        self._apex_queries: Dict[Tuple[str, str], deque] = defaultdict(deque)
        self._last_prune_time = 0.0

    def evaluate(
        self,
        domain_name: str,
        qtype_name: str,
        packet: ParsedPacket,
        next_alert_id_fn: callable,
        now: float,
        txt_records: Optional[List[str]] = None,
    ) -> List[IDSAlert]:
        """
        Evaluates a DNS query or response for covert tunneling and high-churn characteristics.
        """
        clean_domain = domain_name.strip().lower().rstrip(".")
        if not clean_domain:
            return []

        # Skip local/infra
        if any(clean_domain.endswith(ext) for ext in (".arpa", ".local", ".internal", ".lan", ".localhost")):
            return []

        self._prune_expired(now)

        src_ip, dst_ip, src_port, dst_port = get_packet_endpoints(packet)

        is_cdn = is_cdn_or_cloud_domain(clean_domain)
        apex, subdomain = extract_apex_and_subdomain(clean_domain)
        sub_labels = subdomain.split(".") if subdomain else []
        longest_sub_label = max(sub_labels, key=len) if sub_labels else ""

        # Vector 1: Structural Length (Weight: 1.5)
        # RFC 1035 limits: 63 per label, 255 total. Legitimate queries rarely exceed 100 total or 40 in sublabel.
        v1_length_triggered = (len(clean_domain) >= 100 or len(longest_sub_label) >= 40)

        # Vector 2: Encoded Data Pattern (Weight: 1.5)
        # Checks for Base32, Hex, or Base64 encoding without common word delimiters
        v2_encoding_triggered = False
        encoding_type = ""
        if longest_sub_label:
            if HEX_REGEX.match(longest_sub_label):
                v2_encoding_triggered = True
                encoding_type = "Hex"
            elif BASE32_REGEX.match(longest_sub_label):
                v2_encoding_triggered = True
                encoding_type = "Base32"
            elif BASE64_SUBDOMAIN_REGEX.match(longest_sub_label):
                v2_encoding_triggered = True
                encoding_type = "Base64"

        # Vector 3: High Subdomain Entropy (Weight: 1.0)
        v3_entropy_triggered = False
        sub_entropy = 0.0
        if len(longest_sub_label) >= 25:
            sub_entropy = calculate_entropy(longest_sub_label)
            # Hex theoretical max is 4.0 (16 symbols); Base32/Base64 theoretical max is 5.0-6.0
            min_sub_ent = 3.6 if (v2_encoding_triggered and encoding_type == "Hex") else 4.0
            if sub_entropy >= min_sub_ent:
                v3_entropy_triggered = True

        # Vector 4: Subdomain Churn Tracking (Composite Weight: 1.5)
        # Tracks high-frequency distinct subdomains querying the exact same apex
        v4_churn_triggered = False
        churn_count = 0
        dedicated_churn_triggered = False
        churn_threshold = 25

        if apex and subdomain:
            key = (src_ip, apex)
            # Enforce max tracked entries limit
            if key not in self._apex_queries and len(self._apex_queries) >= self.max_apex_tracked:
                oldest_key = min(
                    self._apex_queries.keys(),
                    key=lambda k: self._apex_queries[k][0][0] if self._apex_queries[k] else 0,
                )
                del self._apex_queries[oldest_key]

            q_queue = self._apex_queries[key]
            q_queue.append((now, clean_domain, len(longest_sub_label), sub_entropy, v2_encoding_triggered))

            # Count unique subdomains in window using set comprehension
            # Repeated identical queries do not inflate unique count
            recent_subs = {item[1] for item in q_queue if now - item[0] <= self.window_seconds}
            churn_count = len(recent_subs)

            # CDN tolerance: CDNs resolve many edge shards; use threshold of 100
            is_cdn = is_cdn_or_cloud_domain(clean_domain)
            churn_threshold = 100 if is_cdn else 25

            if churn_count >= (100 if is_cdn else 20):
                v4_churn_triggered = True

            # Dedicated high-churn rule trigger check
            if churn_count >= churn_threshold:
                dedicated_churn_triggered = True

            # Issue 3: Rolling Behavioral Analysis for Low-and-Slow DNS Tunneling
            # Detects low-frequency exfiltration spanning multiple minutes (up to 300s window)
            # where queries are spaced out to evade short churn thresholds.
            low_and_slow_triggered = False
            slow_evidence = ""
            slow_window = 300.0
            slow_queries = [
                item for item in q_queue
                if now - item[0] <= slow_window
            ]
            min_slow_count = 20 if is_cdn else 8
            min_slow_len = 35 if is_cdn else 20
            if len(slow_queries) >= min_slow_count:
                unique_qnames = {item[1] for item in slow_queries}
                uniqueness_ratio = len(unique_qnames) / len(slow_queries)
                encoded_count = sum(1 for item in slow_queries if item[4])
                encoded_ratio = encoded_count / len(slow_queries)
                avg_entropy = sum(item[3] for item in slow_queries) / len(slow_queries)
                avg_len = sum(item[2] for item in slow_queries) / len(slow_queries)

                if (
                    uniqueness_ratio >= 0.80
                    and encoded_ratio >= 0.70
                    and avg_entropy >= 3.4
                    and avg_len >= min_slow_len
                ):
                    low_and_slow_triggered = True
                    span = now - slow_queries[0][0]
                    slow_evidence = (
                        f"Low-and-Slow DNS Tunneling to '{apex}': {len(unique_qnames)} unique "
                        f"encoded queries ({encoded_ratio * 100:.0f}%) over {span:.1f}s, "
                        f"avg entropy {avg_entropy:.2f}, avg label len {avg_len:.1f}"
                    )
        else:
            low_and_slow_triggered = False
            slow_evidence = ""

        # Vector 5: Unusual Query Type (Weight: 0.5)
        # Note: Weight is 0.5; with a threshold of 3.5, an unusual query type alone can NEVER trigger an alert.
        v5_type_triggered = (qtype_name.upper() in ("TXT", "NULL", "CNAME", "ANY"))

        # Check for TXT content in responses or inspection
        txt_exempted = False
        if txt_records:
            for txt_val in txt_records:
                if is_legitimate_txt_record(txt_val):
                    # Crucial: Legitimate SPF/DKIM/DMARC only exempts Vector 5 (TXT content),
                    # it does NOT suppress independent structural or high-volume churn exfiltration!
                    txt_exempted = True
                    break

        if txt_exempted and v5_type_triggered:
            v5_type_triggered = False

        alerts: List[IDSAlert] = []

        # Composite score accumulation (Standard weight: 1.5 for churn)
        composite_score = (
            (1.5 if v1_length_triggered else 0.0)
            + (1.5 if v2_encoding_triggered else 0.0)
            + (1.0 if v3_entropy_triggered else 0.0)
            + (1.5 if v4_churn_triggered else 0.0)
            + (0.5 if v5_type_triggered else 0.0)
        )

        # 1. Composite Tunneling Path:
        # Standard threshold is strictly >= 3.5 (requiring at least 3 independent vectors).
        # For recognized CDN/cloud infrastructure, single-query noise is attenuated to threshold 4.5
        # so confirmed strong signals (Length + Encoding + Entropy + Type) or multi-query churn trigger,
        # without allowing CDN status to act as a complete detection bypass.
        required_threshold = 4.5 if (is_cdn and not v4_churn_triggered) else 3.5

        if composite_score >= required_threshold:
            indicators = []
            if v1_length_triggered:
                indicators.append(f"Length(FQDN={len(clean_domain)}, Label={len(longest_sub_label)})")
            if v2_encoding_triggered:
                indicators.append(f"Encoding={encoding_type}")
            if v3_entropy_triggered:
                indicators.append(f"Entropy={sub_entropy:.2f}")
            if v4_churn_triggered:
                indicators.append(f"SubdomainChurn={churn_count}/{self.window_seconds:.0f}s")
            if v5_type_triggered:
                indicators.append(f"UnusualQType={qtype_name}")

            evidence = (
                f"DNS Tunneling Characteristics (Composite Score: {composite_score:.1f}/{required_threshold:.1f}): "
                f"Domain '{clean_domain[:64]}' to apex '{apex}' exhibited [{', '.join(indicators)}]."
            )

            alerts.append(
                IDSAlert.create(
                    alert_id=next_alert_id_fn(),
                    timestamp=now,
                    source_ip=src_ip,
                    destination_ip=dst_ip,
                    source_port=src_port,
                    destination_port=dst_port,
                    protocol="DNS",
                    category=DetectionCategory.DNS_TUNNELING,
                    severity=Severity.HIGH,
                    matched_rule="DNS Tunneling Pattern Detected",
                    evidence=evidence[:256],
                    recommended_action=DecisionAction.ALERT,
                    packet_id=packet.packet_id,
                )
            )

        # 2. Low-and-Slow Covert Channel Path: Multi-request rolling behavioral analysis
        elif low_and_slow_triggered:
            alerts.append(
                IDSAlert.create(
                    alert_id=next_alert_id_fn(),
                    timestamp=now,
                    source_ip=src_ip,
                    destination_ip=dst_ip,
                    source_port=src_port,
                    destination_port=dst_port,
                    protocol="DNS",
                    category=DetectionCategory.DNS_TUNNELING,
                    severity=Severity.HIGH,
                    matched_rule="Low-and-Slow DNS Tunneling Pattern",
                    evidence=slow_evidence[:256],
                    recommended_action=DecisionAction.ALERT,
                    packet_id=packet.packet_id,
                )
            )

        # 3. Dedicated High-Churn Path: Pure Subdomain Burst (Severity: MEDIUM)
        # Triggers when sustained query volume to a single apex exceeds churn threshold
        # even if individual labels are short or non-encoded
        elif dedicated_churn_triggered:
            evidence = (
                f"Dedicated Subdomain Churn: Client {src_ip} queried {churn_count} unique subdomains for "
                f"apex '{apex}' in {self.window_seconds:.0f}s (Threshold: {churn_threshold}). "
                f"High subdomain diversity indicator."
            )
            alerts.append(
                IDSAlert.create(
                    alert_id=next_alert_id_fn(),
                    timestamp=now,
                    source_ip=src_ip,
                    destination_ip=dst_ip,
                    source_port=src_port,
                    destination_port=dst_port,
                    protocol="DNS",
                    category=DetectionCategory.SUSPICIOUS_DNS,
                    severity=Severity.MEDIUM,
                    matched_rule="Excessive Unique Subdomain Generation (DNS Anomaly)",
                    evidence=evidence[:256],
                    recommended_action=DecisionAction.ALERT,
                    packet_id=packet.packet_id,
                )
            )

        return alerts

    def _prune_expired(self, now: float) -> None:
        """Prunes tracking entries older than the rolling window (bounded up to 300s)."""
        if now - self._last_prune_time < 5.0:
            return
        self._last_prune_time = now

        max_history = max(self.window_seconds, 300.0)
        expired_keys = []
        for key, q_queue in self._apex_queries.items():
            while q_queue and now - q_queue[0][0] > max_history:
                q_queue.popleft()
            if not q_queue:
                expired_keys.append(key)

        for key in expired_keys:
            del self._apex_queries[key]
