import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Optional, List, Dict, Any

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text

from data_models import PlaybookResult, Report

logger = logging.getLogger(__name__)

class Reporter:
    """Generates machine-readable JSON and human-readable Rich reports."""

    def __init__(self):
        self.console = Console()
        self.reports_dir = Path("reports")
        self.reports_dir.mkdir(exist_ok=True)

    def generate(self, result: PlaybookResult) -> Report:
        """Generate both JSON and Rich terminal reports from a PlaybookResult.
        
        Spec: Method: generate(result: PlaybookResult) → Report
        """
        alert = result.alert
        vt_result = result.vt_result
        abuse_result = result.abuse_result
        geo_result = result.geo_result
        decision = result.decision
        execution_log = result.execution_log
        total_duration_ms = result.total_duration_ms
        completed_at = result.completed_at

        # 1. Build JSON report (machine-readable)
        json_data = {
            "report_id": str(datetime.now().timestamp()),
            "generated_at": completed_at.isoformat(),
            "alert": {
                "alert_id": alert.alert_id,
                "alert_type": alert.alert_type,
                "source_ip": alert.source_ip,
                "original_timestamp": alert.timestamp.isoformat() if alert.timestamp else None
            },
            "enrichment": {
                "virustotal": self._to_dict(vt_result),
                "abuseipdb": self._to_dict(abuse_result),
                "geolocation": self._to_dict(geo_result)
            },
            "decision": {
                "severity": decision.severity,
                "action": decision.action,
                "confidence": decision.confidence,
                "composite_score": decision.composite_score,
                "reasons": decision.reasons
            },
            "playbook_execution": {
                "total_duration_ms": total_duration_ms,
                "steps": [
                    {"step": s.step_name, "status": s.status, "duration_ms": s.duration_ms} 
                    for s in execution_log
                ]
            }
        }

        # Save JSON to file
        report_filename = f"{alert.alert_id}_{int(completed_at.timestamp())}.json"
        report_path = self.reports_dir / report_filename
        try:
            with open(report_path, "w") as f:
                json.dump(json_data, f, indent=4)
        except Exception as e:
            logger.error(f"Failed to save JSON report: {e}")

        # 2. Build Rich Summary (human-readable)
        text_summary = self._build_rich_summary(result)

        return Report(
            json_report=json_data,
            text_summary=text_summary,
            report_path=str(report_path)
        )

    def _to_dict(self, obj: Any) -> Optional[Dict[str, Any]]:
        """Convert dataclass to dict, handling None."""
        if not obj: return None
        return {k: v for k, v in obj.__dict__.items() if k != 'raw_response'}

    def _build_rich_summary(self, result: PlaybookResult) -> str:
        """Create a professional terminal output using Rich."""
        alert = result.alert
        vt = result.vt_result
        abuse = result.abuse_result
        geo = result.geo_result
        decision = result.decision
        duration = result.total_duration_ms

        console = Console(width=100, record=True)
        
        # Header Panel
        console.print(Panel(
            f"[bold cyan]ID:[/bold cyan] {alert.alert_id} | [bold cyan]TYPE:[/bold cyan] {alert.alert_type}",
            title="🔔 Security Alert Playbook",
            subtitle=f"Analyzed at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
        ))

        # Info Table
        info_table = Table(box=None, padding=(0, 2))
        info_table.add_column("Property", style="dim")
        info_table.add_column("Value", style="bold")
        info_table.add_row("Source IP", alert.source_ip)
        info_table.add_row("Country", geo.country if geo else "Unknown")
        info_table.add_row("ISP/Org", geo.isp if geo else "Unknown")
        console.print(info_table)

        # Enrichment Scores
        score_table = Table(title="\n📊 Enrichment Analysis", show_header=True, header_style="bold magenta")
        score_table.add_column("Engine", style="cyan")
        score_table.add_column("Score", justify="right")
        score_table.add_column("Risk Level")

        vt_score = f"{vt.malicious_score:.1f}%" if vt else "N/A"
        vt_risk = "[red]High[/red]" if (vt and vt.malicious_score > 50) else "[green]Low[/green]"
        score_table.add_row("VirusTotal (Malicious %)", vt_score, vt_risk)

        abuse_score = f"{abuse.abuse_confidence_score}/100" if abuse else "N/A"
        abuse_risk = "[red]High[/red]" if (abuse and abuse.abuse_confidence_score > 50) else "[green]Low[/green]"
        score_table.add_row("AbuseIPDB (Confidence)", abuse_score, abuse_risk)
        
        console.print(score_table)

        # Verdict Panel
        severity_colors = {
            "CRITICAL": "white on red",
            "HIGH": "red",
            "MEDIUM": "yellow",
            "LOW": "green"
        }
        color = severity_colors.get(decision.severity, "white")
        
        console.print(Panel(
            f"[bold {color}]VERDICT: {decision.severity} - {decision.action}[/bold {color}]\n" +
            "\n".join([f"• {r}" for r in decision.reasons]),
            title="⚖️ Decision Engine Result",
            border_style=color.split()[-1]
        ))

        console.print(f"[dim]Playbook execution completed in {duration}ms[/dim]")
        
        return console.export_text()