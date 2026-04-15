"""
Advanced Correlation Engine for the Integrated Detection System.

Links network attack events (Snort) with malware behaviours (YARA, CAPEv2)
by matching IoCs across five dimensions: IP address, domain name,
file hash, and behaviour/TTP similarity, with a multiplicative
temporal proximity booster. Assigns weighted scores to produce
unified threat correlation reports.
"""

import logging
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from . import config
from .plugin_framework import (
    Alert, AnalysisResult, AnalysisSource, IoC, IoCType,
)
from .utils import timestamps_within_window


logger = logging.getLogger(__name__)


# ============================================================================
# Data Models
# ============================================================================

@dataclass
class CorrelationMatch:
    """A single correlation match between two alerts."""
    alert_id_1: str
    alert_id_2: str
    correlation_type: str   # ip_address, domain, file_hash, time_window
    matched_value: str      # The IoC value that matched
    weight: float           # Weight from config
    details: Dict = field(default_factory=dict)

    def to_dict(self) -> Dict:
        return {
            "alert_id_1": self.alert_id_1,
            "alert_id_2": self.alert_id_2,
            "correlation_type": self.correlation_type,
            "matched_value": self.matched_value,
            "weight": self.weight,
            "details": self.details,
        }


@dataclass
class CorrelationReport:
    """Aggregated correlation between two alerts across all dimensions."""
    alert_id_1: str
    alert_id_2: str
    source_1: str
    source_2: str
    total_score: float
    matches: List[CorrelationMatch] = field(default_factory=list)
    is_correlated: bool = False

    def to_dict(self) -> Dict:
        return {
            "alert_id_1": self.alert_id_1,
            "alert_id_2": self.alert_id_2,
            "source_1": self.source_1,
            "source_2": self.source_2,
            "total_score": round(self.total_score, 4),
            "is_correlated": self.is_correlated,
            "matches": [m.to_dict() for m in self.matches],
            "match_count": len(self.matches),
        }


# ============================================================================
# Correlation Engine
# ============================================================================

class CorrelationEngine:
    """
    5-Dimension correlation engine with multiplicative temporal boosting.

    Compares alerts from different analysis sources and identifies
    linked events based on shared IoCs with weighted scoring.

    Additive dimensions: IP, Domain, File Hash, Behaviour/TTP.
    Multiplicative booster: Time Window (amplifies existing matches).
    """

    def __init__(
        self,
        weights: Optional[Dict[str, float]] = None,
        threshold: Optional[float] = None,
        time_window: Optional[int] = None,
        time_boost: Optional[float] = None,
    ):
        self.weights = weights or config.CORRELATION_WEIGHTS
        self.threshold = threshold or config.CORRELATION_THRESHOLD
        self.time_window = time_window or config.CORRELATION_TIME_WINDOW
        self.time_boost = time_boost or getattr(
            config, "CORRELATION_TIME_BOOST", 1.3
        )

        # Validate weights sum to ~1.0
        total_weight = sum(self.weights.values())
        if abs(total_weight - 1.0) > 0.01:
            logger.warning(
                f"Correlation weights sum to {total_weight}, "
                f"expected 1.0. Normalising."
            )
            for k in self.weights:
                self.weights[k] /= total_weight

        self._alerts: List[Alert] = []
        self._results: List[CorrelationReport] = []

    def add_alerts(self, alerts: List[Alert]):
        """Add alerts for correlation analysis."""
        self._alerts.extend(alerts)
        logger.info(f"Added {len(alerts)} alerts (total: {len(self._alerts)})")

    def add_analysis_results(self, results: List[AnalysisResult]):
        """Add all alerts from multiple AnalysisResults."""
        for result in results:
            self.add_alerts(result.alerts)

    def correlate(self) -> List[CorrelationReport]:
        """
        Run correlation analysis across all loaded alerts.

        Compares every pair of alerts from DIFFERENT sources.
        Returns only pairs exceeding the correlation threshold.

        Returns:
            List of CorrelationReport objects, sorted by score desc.
        """
        self._results.clear()

        if len(self._alerts) < 2:
            logger.info("Fewer than 2 alerts, nothing to correlate")
            return []

        # Build IoC index for efficient lookup
        ioc_index = self._build_ioc_index()

        # Compare cross-source alert pairs
        pairs_checked = 0
        correlated_count = 0

        for i in range(len(self._alerts)):
            for j in range(i + 1, len(self._alerts)):
                a1 = self._alerts[i]
                a2 = self._alerts[j]

                # Only correlate alerts from DIFFERENT sources
                if a1.source == a2.source:
                    continue

                pairs_checked += 1
                report = self._correlate_pair(a1, a2, ioc_index)

                if report.is_correlated:
                    self._results.append(report)
                    correlated_count += 1

        # Sort by score descending
        self._results.sort(key=lambda r: r.total_score, reverse=True)

        logger.info(
            f"Correlation complete: {pairs_checked} pairs checked, "
            f"{correlated_count} correlated events found"
        )
        return self._results

    def get_results(self) -> List[CorrelationReport]:
        """Return the most recent correlation results."""
        return self._results

    def clear(self):
        """Clear all alerts and results."""
        self._alerts.clear()
        self._results.clear()

    # ====================================================================
    # Core Correlation Logic
    # ====================================================================

    def _correlate_pair(
        self, a1: Alert, a2: Alert, ioc_index: Dict
    ) -> CorrelationReport:
        """
        Correlate a pair of alerts across five dimensions with
        multiplicative temporal boosting.

        Additive Dimensions (IoC-based):
        1. IP Address:  Same IP in both alerts' IoCs
        2. Domain:      Same domain/URL in both alerts' IoCs
        3. File Hash:   Same MD5/SHA256 hash in both alerts' IoCs
        4. Behavior:    Same YARA rule, Snort sig category, or ATT&CK TTP

        Multiplicative Booster:
        5. Time Window: If events are within N seconds, score *= TIME_BOOST
           (temporal proximity alone is NOT evidence; it amplifies IoC matches)
        """
        matches = []
        score = 0.0

        # --- Dimension 1: IP Address ---
        ip_matches = self._match_iocs_by_type(
            a1, a2, [IoCType.IP_ADDRESS], ioc_index
        )
        for matched_value in ip_matches:
            match = CorrelationMatch(
                alert_id_1=a1.alert_id,
                alert_id_2=a2.alert_id,
                correlation_type="ip_address",
                matched_value=matched_value,
                weight=self.weights["ip_address"],
            )
            matches.append(match)
            score += self.weights["ip_address"]

        # --- Dimension 2: Domain Name ---
        domain_matches = self._match_iocs_by_type(
            a1, a2, [IoCType.DOMAIN, IoCType.URL], ioc_index
        )
        for matched_value in domain_matches:
            match = CorrelationMatch(
                alert_id_1=a1.alert_id,
                alert_id_2=a2.alert_id,
                correlation_type="domain",
                matched_value=matched_value,
                weight=self.weights["domain"],
            )
            matches.append(match)
            score += self.weights["domain"]

        # --- Dimension 3: File Hash ---
        # Cap to ONE score contribution regardless of hash type count:
        # matching on both MD5 and SHA256 is the same file, not extra evidence.
        hash_matches = self._match_iocs_by_type(
            a1, a2,
            [IoCType.FILE_HASH_MD5, IoCType.FILE_HASH_SHA256],
            ioc_index,
        )
        if hash_matches:
            # Record only ONE match for scoring (pick the first)
            match = CorrelationMatch(
                alert_id_1=a1.alert_id,
                alert_id_2=a2.alert_id,
                correlation_type="file_hash",
                matched_value=hash_matches[0],
                weight=self.weights["file_hash"],
            )
            matches.append(match)
            score += self.weights["file_hash"]

        # --- Dimension 4: Behavior / TTP ---
        behavior_matches = self._match_behavior(a1, a2)
        for matched_value in behavior_matches:
            match = CorrelationMatch(
                alert_id_1=a1.alert_id,
                alert_id_2=a2.alert_id,
                correlation_type="behavior",
                matched_value=matched_value,
                weight=self.weights["behavior"],
            )
            matches.append(match)
            score += self.weights["behavior"]

        # --- Multiplicative Booster: Time Window ---
        # Temporal proximity amplifies existing IoC evidence but
        # does NOT contribute to the score on its own.
        if score > 0 and timestamps_within_window(
            a1.timestamp, a2.timestamp, self.time_window
        ):
            match = CorrelationMatch(
                alert_id_1=a1.alert_id,
                alert_id_2=a2.alert_id,
                correlation_type="time_window",
                matched_value=(
                    f"{a1.timestamp} <-> {a2.timestamp}"
                ),
                weight=self.time_boost,
            )
            matches.append(match)
            score *= self.time_boost

        # Cap score at 1.0
        score = min(score, 1.0)

        return CorrelationReport(
            alert_id_1=a1.alert_id,
            alert_id_2=a2.alert_id,
            source_1=a1.source.value,
            source_2=a2.source.value,
            total_score=score,
            matches=matches,
            is_correlated=(score >= self.threshold),
        )

    # ====================================================================
    # IoC Matching Helpers
    # ====================================================================

    @staticmethod
    def _match_behavior(a1: Alert, a2: Alert) -> List[str]:
        """
        Match behaviour / TTP indicators between two alerts.

        Checks for overlap in:
        - YARA rule names (stored in alert details or message)
        - Snort signature categories / classtype
        - MITRE ATT&CK technique IDs (if present in details)
        """
        tags_1: set = set()
        tags_2: set = set()

        for alert, tags in [(a1, tags_1), (a2, tags_2)]:
            # YARA rule names and CAPEv2 signature names from details
            for key in ("matched_rules", "yara_rules", "rule_name",
                        "signature_name"):
                val = alert.details.get(key)
                if isinstance(val, list):
                    tags.update(v.lower() for v in val if v)
                elif isinstance(val, str) and val:
                    tags.add(val.lower())

            # Malware family names from CAPEv2
            families = alert.details.get("families", [])
            if isinstance(families, list):
                tags.update(f.lower() for f in families if f)

            # Snort classtype / signature category
            for key in ("classtype", "signature_category", "attack_type"):
                val = alert.details.get(key)
                if isinstance(val, str) and val:
                    tags.add(val.lower())

            # MITRE ATT&CK TTP IDs
            for key in ("mitre_attack", "ttp", "technique_id"):
                val = alert.details.get(key)
                if isinstance(val, list):
                    tags.update(v.upper() for v in val if v)
                elif isinstance(val, str) and val:
                    tags.add(val.upper())

            # Malware family name from YARA rule or alert message
            family = alert.details.get("malware_family", "")
            if family:
                tags.add(family.lower())

        return list(tags_1 & tags_2)

    def _build_ioc_index(self) -> Dict[str, Dict[str, set]]:
        """
        Build an inverted index: IoC value -> set of alert_ids.

        Structure: {ioc_type: {ioc_value: {alert_id, ...}}}
        """
        index = defaultdict(lambda: defaultdict(set))

        for alert in self._alerts:
            for ioc in alert.iocs:
                index[ioc.ioc_type.value][ioc.value].add(alert.alert_id)

            # Also extract IoCs from alert details
            details = alert.details
            for ip_key in ("src_ip", "dst_ip"):
                if ip_key in details and details[ip_key]:
                    index[IoCType.IP_ADDRESS.value][
                        details[ip_key]
                    ].add(alert.alert_id)

        return index

    @staticmethod
    def _match_iocs_by_type(
        a1: Alert, a2: Alert, ioc_types: List[IoCType],
        ioc_index: Dict
    ) -> List[str]:
        """
        Find IoC values shared between two alerts for given types.

        Returns:
            List of matched IoC values.
        """
        # Collect IoC values for each alert
        values_1 = set()
        values_2 = set()

        for ioc in a1.iocs:
            if ioc.ioc_type in ioc_types:
                values_1.add(ioc.value)

        for ioc in a2.iocs:
            if ioc.ioc_type in ioc_types:
                values_2.add(ioc.value)

        # Also check alert details for IPs
        if IoCType.IP_ADDRESS in ioc_types:
            for key in ("src_ip", "dst_ip"):
                if key in a1.details and a1.details[key]:
                    values_1.add(a1.details[key])
                if key in a2.details and a2.details[key]:
                    values_2.add(a2.details[key])

        # Return intersection
        return list(values_1 & values_2)
