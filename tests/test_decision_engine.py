import pytest
from unittest.mock import Mock

from engine.decision_engine import DecisionEngine
from data_models import VirusTotalResult, AbuseIPDBResult, GeolocationResult, Decision

class TestDecisionEngine:
    def setup_method(self):
        self.engine = DecisionEngine()

    def test_critical_decision(self):
        # vt_score=90, abuse=95 -> CRITICAL
        vt = VirusTotalResult("1.2.3.4", 9, 10, 90.0, "CN", "ISP", 100, {}, False)
        abuse = AbuseIPDBResult("1.2.3.4", 95, 10, "date", False, False, "isp", {})
        geo = GeolocationResult("1.2.3.4", "RU", "CA", "SJ", "X", "Y", 0, 0, False, False)
        
        decision = self.engine.evaluate(vt, abuse, geo)
        assert decision.severity == "CRITICAL"
        assert decision.action == "BLOCK"
        # Check for explainable reasons
        assert any("VirusTotal" in r for r in decision.reasons)
        assert any("high-risk region" in r for r in decision.reasons)

    def test_tor_overrides_to_high(self):
        # low scores but is_tor=True
        vt = VirusTotalResult("1.2.3.4", 0, 10, 0.0, "US", "ISP", 100, {}, False)
        abuse = AbuseIPDBResult("1.2.3.4", 0, 0, "date", True, False, "isp", {})
        
        decision = self.engine.evaluate(vt, abuse, None)
        assert decision.severity == "HIGH"
        assert any("TOR exit node detected" in r for r in decision.reasons)

    def test_missing_enrichment_graceful(self):
        decision = self.engine.evaluate(None, None, None)
        assert decision.severity == "LOW"
        assert any("No significant risk indicators" in r for r in decision.reasons)