"""Decision Engine evaluating DPI results and IDS alerts to yield ALLOW / ALERT / BLOCK."""

from __future__ import annotations

import logging
from typing import Dict, List, Optional, Set

from models.alert_model import DecisionAction, DetectionCategory, DPIResult, IDSAlert, Severity
from models.flow_model import Flow
from models.packet_models import ParsedPacket

logger = logging.getLogger("dpi_ids_ips.ips.decision_engine")

# Categories that are strictly advisory and must never directly trigger a BLOCK
ADVISORY_ONLY_CATEGORIES: Set[DetectionCategory] = {
    DetectionCategory.ML_CLASSIFICATION,
    DetectionCategory.ML_ANOMALY,
    DetectionCategory.DNS_TUNNELING,
    DetectionCategory.SUSPICIOUS_DNS,
}


class DecisionEngine:
    """Arbiter that decides whether to ALLOW, ALERT, or BLOCK traffic."""

    def __init__(self) -> None:
        self.decision_counts: Dict[str, int] = {
            DecisionAction.ALLOW.value: 0,
            DecisionAction.ALERT.value: 0,
            DecisionAction.BLOCK.value: 0,
        }

    def decide(
        self,
        packet: ParsedPacket,
        dpi_result: Optional[DPIResult],
        alerts: List[IDSAlert],
        flow: Optional[Flow] = None,
    ) -> DecisionAction:
        """
        Determines the appropriate security action.

        Policy precedence:
            1. Confirmed malicious activity: BLOCK, subject to policy restrictions:
               - ML predictions are advisory only; never directly block.
               - DNS tunneling suspicion is ALERT only by default.
               - Unknown domains are never blocked solely because they are unknown.
               - Informational / Low / Medium confidence: ALERT only.
               - High confidence: ALERT only unless corroborated by strong independent evidence
                 (recommended_action == DecisionAction.BLOCK).
               - An alert cannot automatically become a block merely because its severity is HIGH.
            2. Any remaining alerts: ALERT.
            3. Benign traffic without alerts: ALLOW.

        Args:
            packet: ParsedPacket.
            dpi_result: DPIResult.
            alerts: List of IDSAlerts.
            flow: Associated Flow.

        Returns:
            DecisionAction enum (ALLOW, ALERT, or BLOCK).
        """
        action = DecisionAction.ALLOW

        if alerts:
            has_block = any(self._is_blockable_alert(a) for a in alerts)
            if has_block:
                action = DecisionAction.BLOCK
            else:
                action = DecisionAction.ALERT

        self.decision_counts[action.value] = self.decision_counts.get(action.value, 0) + 1
        return action

    @staticmethod
    def _is_blockable_alert(alert: IDSAlert) -> bool:
        """
        Validates whether an IDS alert qualifies for an active BLOCK decision.
        Enforces strict authorization:
        - Explicit blocking authorization is required (recommended_action == DecisionAction.BLOCK).
        - Severity alone (even CRITICAL or HIGH) never independently authorizes blocking.
        - Advisory categories (ML, DNS tunneling, suspicious DNS) and unknown domains never block.
        """
        # Explicit blocking recommendation is strictly required
        if alert.recommended_action != DecisionAction.BLOCK:
            return False

        # ML predictions: ALERT only, never directly block
        if alert.category in (DetectionCategory.ML_CLASSIFICATION, DetectionCategory.ML_ANOMALY):
            return False

        # DNS tunneling suspicion: ALERT only by default
        if alert.category in (DetectionCategory.DNS_TUNNELING, DetectionCategory.SUSPICIOUS_DNS):
            return False

        # Unknown domain must never block solely because it is unknown
        rule_lower = (alert.matched_rule or "").lower()
        evidence_lower = (alert.evidence or "").lower()
        if "unknown domain" in rule_lower or "unknown domain" in evidence_lower:
            return False

        # Confirmed malicious activity with explicit corroborated BLOCK authorization
        return True
