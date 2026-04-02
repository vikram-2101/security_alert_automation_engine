from typing import Optional, List
from data_models import Decision, VirusTotalResult, AbuseIPDBResult, GeolocationResult

class DecisionEngine:
    """The brain of the playbook — weighted scoring and explainable decision logic."""

    # DESIGN: High-risk countries based on common threat intel datasets.
    HIGH_RISK_COUNTRIES = ["CN", "RU", "KP", "IR", "NG"]

    def evaluate(self, vt: Optional[VirusTotalResult], abuse: Optional[AbuseIPDBResult], geo: Optional[GeolocationResult]) -> Decision:
        """Evaluate enrichment data and return a weighted, explainable decision.
        
        Logic: 
        - VirusTotal (50%): Primary indicator of known malicious intent.
        - AbuseIPDB (35%): Indicator of recent abusive behavior/reporting.
        - Geolocation (15%): Supporting indicator (Proxy, Hosting, High-Risk Country).
        """
        vt_score = vt.malicious_score if vt else 0.0
        abuse_score = float(abuse.abuse_confidence_score) if abuse else 0.0
        
        # Calculate Geo Risk (Supporting indicator)
        geo_risk_score, geo_reasons = self._calculate_geo_risk(geo, abuse)

        # DESIGN: Weighted scoring for defensible triage.
        composite_score = (
            vt_score * 0.50 +
            abuse_score * 0.35 +
            geo_risk_score * 0.15
        )

        # Determine Severity & Action
        if composite_score >= 70:
            severity = "CRITICAL"
            action = "BLOCK"
        elif composite_score >= 45:
            severity = "HIGH"
            action = "INVESTIGATE"
        elif composite_score >= 20:
            severity = "MEDIUM"
            action = "MONITOR"
        else:
            severity = "LOW"
            action = "MONITOR"

        # Special Override: TOR Nodes
        is_tor = abuse and abuse.is_tor
        if is_tor and severity in ["LOW", "MEDIUM"]:
            severity = "HIGH"
            action = "INVESTIGATE"

        # Explainable Reasoning
        reasons = self._build_explainable_reasons(vt, abuse, geo, geo_reasons, is_tor)

        return Decision(
            severity=severity,
            action=action,
            confidence=95.0 if vt and abuse and geo else 60.0,
            reasons=reasons,
            composite_score=composite_score
        )

    def _calculate_geo_risk(self, geo: Optional[GeolocationResult], abuse: Optional[AbuseIPDBResult]) -> (float, List[str]):
        """Calculate geo risk score and capture specific reasons."""
        score = 0.0
        reasons = []
        if not geo: return 0.0, []

        if geo.is_proxy:
            score += 40
            reasons.append("Connection identified as a Proxy")
        if geo.is_hosting:
            score += 30
            reasons.append("IP belongs to a Hosting/Data Center provider")
        if geo.country in self.HIGH_RISK_COUNTRIES:
            score += 30
            reasons.append(f"Source located in high-risk region: {geo.country}")
        
        if abuse and abuse.is_tor:
            score += 50
            # Note: TOR is also handled as an override in evaluate()
        
        return min(score, 100.0), reasons

    def _build_explainable_reasons(self, vt: Optional[VirusTotalResult], abuse: Optional[AbuseIPDBResult], 
                                   geo: Optional[GeolocationResult], geo_reasons: List[str], is_tor: bool) -> List[str]:
        """Build detailed, human-readable reasons (Explainable Scoring)."""
        reasons = []

        # VT Reasons
        if vt:
            if vt.malicious_count > 0:
                reasons.append(f"IP flagged by VirusTotal ({vt.malicious_count} engines)")
            if vt.reputation < 0:
                reasons.append(f"Negative VirusTotal community reputation: {vt.reputation}")
        
        # Abuse Reason
        if abuse:
            if abuse.abuse_confidence_score > 50:
                reasons.append(f"High abuse confidence reported on AbuseIPDB ({abuse.abuse_confidence_score}%)")
            if abuse.total_reports > 10:
                reasons.append(f"Frequent abusive behavior detected ({abuse.total_reports} reports)")
        
        # Geo Reasons
        if geo:
            reasons.extend(geo_reasons)
            if not geo_reasons:
                reasons.append(f"Geolocation: {geo.city}, {geo.country} (No specific risk factors)")
        
        # TOR Override Reason
        if is_tor:
            reasons.append("TOR exit node detected (Automated severity elevation to HIGH)")

        if not reasons:
            reasons.append("No significant risk indicators identified")

        return reasons