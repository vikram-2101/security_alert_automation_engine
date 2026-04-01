from dataclasses import dataclass
from datetime import datetime
from typing import Dict, List, Any, Optional

@dataclass
class Alert:
    """Normalized alert object."""
    alert_id: str
    alert_type: str
    severity_input: str
    source_ip: str
    timestamp: datetime
    raw: Dict[str, Any]
    metadata: Dict[str, Any]

@dataclass
class VirusTotalResult:
    """VirusTotal enrichment result."""
    ip: str
    malicious_count: int
    total_engines: int
    malicious_score: float
    country: str
    asn_owner: str
    reputation: int
    raw_response: Dict[str, Any]
    not_found: bool = False

@dataclass
class AbuseIPDBResult:
    """AbuseIPDB enrichment result."""
    ip: str
    abuse_confidence_score: int
    total_reports: int
    last_reported_at: str
    is_tor: bool
    is_datacenter: bool
    usage_type: str
    raw_response: Dict[str, Any]

@dataclass
class GeolocationResult:
    """Geolocation enrichment result."""
    ip: str
    country: str
    region: str
    city: str
    isp: str
    org: str
    latitude: float
    longitude: float
    is_proxy: bool
    is_hosting: bool

@dataclass
class Decision:
    """Decision result."""
    severity: str  # "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO"
    action: str  # "BLOCK" | "INVESTIGATE" | "MONITOR" | "WHITELIST"
    confidence: float  # 0-100
    reasons: List[str]
    composite_score: float

@dataclass
class PlaybookStep:
    """Execution step in playbook."""
    step_name: str
    status: str  # "success" | "failed" | "skipped"
    duration_ms: int
    error: Optional[str] = None

@dataclass
class PlaybookResult:
    """Playbook execution result."""
    alert: Alert
    vt_result: Optional[VirusTotalResult]
    abuse_result: Optional[AbuseIPDBResult]
    geo_result: Optional[GeolocationResult]
    decision: Decision
    execution_log: List[PlaybookStep]
    total_duration_ms: int
    completed_at: datetime

@dataclass
class Report:
    """Generated report."""
    json_report: Dict[str, Any]
    text_summary: str
    report_path: str

# Custom exceptions
class ConfigError(Exception):
    """Configuration error."""
    pass

class RateLimitError(Exception):
    """API rate limit exceeded."""
    pass

class EnrichmentError(Exception):
    """Enrichment API error."""
    pass