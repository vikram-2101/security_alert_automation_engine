import time
import logging
from datetime import datetime
from typing import Union

from .alert_parser import AlertParser, AlertParseError, PrivateIPError
from .enrichers.virustotal import VirusTotalEnricher, ConfigError as VTConfigError, RateLimitError as VTRateLimitError, EnrichmentError as VTEnrichmentError
from .enrichers.abuseipdb import AbuseIPDBEnricher, ConfigError as AbuseConfigError, RateLimitError as AbuseRateLimitError, EnrichmentError as AbuseEnrichmentError
from .enrichers.geolocation import GeolocationEnricher
from .decision_engine import DecisionEngine
from .reporter import Reporter
from .audit_logger import AuditLogger
from data_models import PlaybookResult, PlaybookStep

logger = logging.getLogger(__name__)

class Playbook:
    """Orchestrates the security alert automation playbook execution."""

    def __init__(self):
        self.parser = AlertParser()
        self.vt_enricher = VirusTotalEnricher()
        self.abuse_enricher = AbuseIPDBEnricher()
        self.geo_enricher = GeolocationEnricher()
        self.decision_engine = DecisionEngine()
        self.reporter = Reporter()
        self.audit_logger = AuditLogger()

    def run(self, alert_source: Union[str, dict]) -> PlaybookResult:
        """Run the playbook stages in sequence.
        
        DESIGN: Enrichment failures must NEVER stop the playbook. 
        If an API is down, we continue with degraded data.
        """
        execution_log = []
        start_time = time.time()

        # 1. Parse Alert (Critical)
        parse_start = time.time()
        try:
            alert = self.parser.parse(alert_source)
            execution_log.append(PlaybookStep("parse_alert", "success", int((time.time() - parse_start) * 1000)))
        except (AlertParseError, PrivateIPError) as e:
            execution_log.append(PlaybookStep("parse_alert", "failed", int((time.time() - parse_start) * 1000), str(e)))
            raise

        # 2-4. Enrichment (Non-critical)
        vt_result = self._run_step("enrich_virustotal", self.vt_enricher.enrich, execution_log, alert.source_ip)
        abuse_result = self._run_step("enrich_abuseipdb", self.abuse_enricher.enrich, execution_log, alert.source_ip)
        geo_result = self._run_step("enrich_geolocation", self.geo_enricher.enrich, execution_log, alert.source_ip)

        # 5. Evaluate Decision (Critical)
        decision_start = time.time()
        try:
            decision = self.decision_engine.evaluate(vt_result, abuse_result, geo_result)
            execution_log.append(PlaybookStep("evaluate_decision", "success", int((time.time() - decision_start) * 1000)))
        except Exception as e:
            execution_log.append(PlaybookStep("evaluate_decision", "failed", int((time.time() - decision_start) * 1000), str(e)))
            raise

        total_duration_ms = int((time.time() - start_time) * 1000)
        completed_at = datetime.now()

        result = PlaybookResult(
            alert=alert, vt_result=vt_result, abuse_result=abuse_result,
            geo_result=geo_result, decision=decision, execution_log=execution_log,
            total_duration_ms=total_duration_ms, completed_at=completed_at
        )

        # 6. Generate Report (Non-blocking)
        self._run_step("generate_report", self.reporter.generate, execution_log, result)

        # 7. Audit Log (Non-blocking)
        self._run_step("audit_log", self._log_to_audit, execution_log, result)

        return result

    def _run_step(self, name, func, log, *args):
        """Helper to run a step and log its status."""
        start = time.time()
        try:
            res = func(*args)
            log.append(PlaybookStep(name, "success", int((time.time() - start) * 1000)))
            return res
        except Exception as e:
            logger.warning(f"Step {name} failed: {e}")
            log.append(PlaybookStep(name, "failed", int((time.time() - start) * 1000), str(e)))
            return None

    def _log_to_audit(self, result: PlaybookResult):
        """Wrapper for audit logger."""
        self.audit_logger.log_run(
            result.alert, result.vt_result, result.abuse_result,
            result.geo_result, result.decision, result.execution_log,
            result.total_duration_ms, result.completed_at
        )