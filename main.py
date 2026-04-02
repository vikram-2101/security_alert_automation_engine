import argparse
import json
import logging
import sys
import asyncio
from pathlib import Path
from rich.console import Console
from rich.panel import Panel

from engine.playbook import Playbook
from engine.reporter import Reporter
from engine.audit_logger import AuditLogger

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

console = Console()

async def main():
    parser = argparse.ArgumentParser(description="Security Alert Automation Engine")
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # run command
    run_parser = subparsers.add_parser("run", help="Run playbook on an alert")
    run_parser.add_argument("--alert", required=True, help="Path to JSON alert file")
    run_parser.add_argument("--dir", action="store_true", help="Treat --alert as a directory")

    # stats command
    subparsers.add_parser("stats", help="Show audit statistics")

    # history command
    history_parser = subparsers.add_parser("history", help="Show recent runs")
    history_parser.add_argument("--limit", type=int, default=10, help="Number of records")

    # test-apis command
    subparsers.add_parser("test-apis", help="Test API connectivity")

    args = parser.parse_args()

    if args.command == "run":
        await run_engine(args.alert, args.dir)
    elif args.command == "stats":
        display_stats()
    elif args.command == "history":
        display_history(args.limit)
    elif args.command == "test-apis":
        await test_apis_logic()
    else:
        parser.print_help()

async def run_engine(path: str, is_dir: bool):
    """Orchestrate the run command asynchronously."""
    playbook = Playbook()
    reporter = Reporter()
    
    target = Path(path)
    if is_dir:
        files = list(target.glob("*.json"))
        if not files:
            console.print(f"[yellow]No alerts found in {path}[/yellow]")
            return
        
        for f in files:
            console.print(f"[cyan]Processing {f.name}...[/cyan]")
            await _execute_single(playbook, reporter, f)
    else:
        await _execute_single(playbook, reporter, target)

async def _execute_single(playbook: Playbook, reporter: Reporter, file_path: Path):
    try:
        # DESIGN: Playbook.run is now async to support parallel enrichment.
        result = await playbook.run(str(file_path))
        
        # reporter.generate returns a Report object containing text_summary.
        report = reporter.generate(result)
        console.print(report.text_summary)
        console.print(f"[green]Report saved to: {report.report_path}[/green]")
        
    except Exception as e:
        console.print(f"[bold red]Critical Error processing {file_path.name}: {e}[/bold red]")
        logger.exception("Single execution failed")

def display_stats():
    """Display audit statistics (Sync)."""
    audit = AuditLogger()
    stats = audit.get_stats()
    
    if not stats:
        console.print("[yellow]No data available in audit log.[/yellow]")
        return
        
    console.print(Panel("[bold blue]Security Automation Engine Statistics[/bold blue]"))
    console.print(f"• Total Playbook Runs: {stats['total_runs']}")
    console.print(f"• Average Duration: {stats['avg_duration_ms']:.1f}ms")
    
    if stats.get('severity_counts'):
        console.print("\n[bold]Severity Distribution:[/bold]")
        for sev, count in stats['severity_counts'].items():
            console.print(f"  - {sev}: {count}")

def display_history(limit: int):
    """Display recent execution history (Sync)."""
    audit = AuditLogger()
    runs = audit.get_runs(limit)
    
    if not runs:
        console.print("[yellow]No history found.[/yellow]")
        return
        
    from rich.table import Table
    table = Table(title="Recent Playbook Runs")
    table.add_column("Alert ID", style="cyan")
    table.add_column("IP", style="green")
    table.add_column("Result", style="bold")
    table.add_column("Action")
    
    for r in runs:
        table.add_row(
            r.get('alert_id', 'N/A'),
            r.get('source_ip', 'N/A'),
            r.get('decision_severity', 'N/A'),
            r.get('decision_action', 'N/A')
        )
    console.print(table)

async def test_apis_logic():
    """Verify connectivity to all 3 external APIs asynchronously."""
    from engine.enrichers.virustotal import VirusTotalEnricher
    from engine.enrichers.abuseipdb import AbuseIPDBEnricher
    from engine.enrichers.geolocation import GeolocationEnricher
    import aiohttp
    
    test_ip = "8.8.8.8"
    console.print(f"[blue]Testing API connectivity (Async) with IP: {test_ip}[/blue]\n")
    
    async with aiohttp.ClientSession() as session:
        vt = VirusTotalEnricher()
        abuse = AbuseIPDBEnricher()
        geo = GeolocationEnricher()
        
        tasks = [
            ("VirusTotal", vt.enrich(test_ip, session)),
            ("AbuseIPDB", abuse.enrich(test_ip, session)),
            ("Geolocation", geo.enrich(test_ip, session))
        ]
        
        for name, task in tasks:
            try:
                await task
                console.print(f"  [green]✅ {name}: Connection Successful[/green]")
            except Exception as err:
                console.print(f"  [red]❌ {name}: Failed ({err})[/red]")

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        sys.exit(0)