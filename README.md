# Security Alert Automation Engine

A Python-based SOAR (Security Orchestration, Automation and Response) playbook that automates security alert triage, reducing manual analysis time from 15 minutes to under 5 seconds.

## What is SOAR?

SOAR platforms enable security teams to collect data about security threats and respond to them in a consistent and effective manner. This project simulates a real SOAR playbook by automating the repetitive tasks of alert enrichment and decision-making, allowing SOC analysts to focus on high-value investigation work.

## Architecture

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   Raw Alert     │ -> │   Alert Parser   │ -> │   Structured    │
│   (JSON/Dict)   │    │   (Validation)   │    │   Alert Object  │
└─────────────────┘    └──────────────────┘    └─────────────────┘
                                                            │
                                                            ▼
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│ VirusTotal      │ -> │   Enrichment     │ -> │   Decision      │
│ AbuseIPDB       │    │   Pipeline       │    │   Engine        │
│ Geolocation     │    │                  │    │                 │
└─────────────────┘    └──────────────────┘    └─────────────────┘
                                                            │
                                                            ▼
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   Rich Report   │ <- │   Reporter       │ <- │   Playbook      │
│   (Terminal)    │    │   (JSON + Text)  │    │   Orchestrator   │
└─────────────────┘    └──────────────────┘    └─────────────────┘
                                                            │
                                                            ▼
┌─────────────────┐    ┌──────────────────┐
│   Audit Log     │ <- │   SQLite DB      │
│   (Stats)       │    │   (Metrics)      │
└─────────────────┘    └──────────────────┘
```

## Features

- **Automated Alert Parsing**: Handles multiple JSON formats with IP extraction
- **Multi-Source Enrichment**: VirusTotal, AbuseIPDB, and geolocation data
- **Intelligent Decision Engine**: Weighted scoring with configurable thresholds
- **Rich Terminal Output**: Color-coded reports with tables and panels
- **Comprehensive Audit Logging**: SQLite-based execution tracking and statistics
- **CLI Interface**: Command-line tools for running, testing, and monitoring
- **Error Resilience**: Graceful handling of API failures and rate limits
- **Extensible Design**: Modular architecture for adding new enrichers

## Setup

### Prerequisites

- Python 3.10+
- Free API keys from VirusTotal and AbuseIPDB

### Installation

1. **Clone the repository**

   ```bash
   git clone <repository-url>
   cd alert-automation-engine
   ```

2. **Install dependencies**

   ```bash
   pip install -r requirements.txt
   ```

3. **Configure environment**

   ```bash
   cp .env.example .env
   # Edit .env with your API keys
   ```

4. **Get API keys**
   - [VirusTotal](https://www.virustotal.com/gui/join-us) - Free tier: 500 requests/day
   - [AbuseIPDB](https://www.abuseipdb.com/register) - Free tier: 1000 requests/day

5. **Verify setup**
   ```bash
   python main.py test-apis
   ```

## Usage

### Run a single alert

```bash
python main.py run alerts/sample_alert_1.json
```

### Run all alerts in directory

```bash
python main.py run --dir alerts/
```

### View audit statistics

```bash
python main.py stats
```

### Show recent runs

```bash
python main.py history --limit 10
```

### Test API connections

```bash
python main.py test-apis
```

## Sample Output

```
Security Alert Automation Report
Alert ID: ALT-2024-001
Execution Time: 2.34s
Success: ✅

Decision: HIGH - INVESTIGATE
Confidence: 78.5%
Reasoning: VirusTotal: 24/90 engines flagged as malicious (26.7%); AbuseIPDB: confidence score 85/100, 47 total reports; Geolocation: Hosting/datacenter IP (+20 risk); TOR exit node detected — severity elevated to HIGH minimum

┌─────────────────┬─────────┬─────────────────────┬─────────────────────────────────────────────────┐
│ Step            │ Status  │ Timestamp           │ Result                                          │
├─────────────────┼─────────┼─────────────────────┼─────────────────────────────────────────────────┤
│ parse_alert     │ ✅      │ 14:32:15            │ Parsed alert ALT-2024-001                       │
│ enrich_virustotal│ ✅      │ 14:32:16            │ Enriched with VT: 24/90 malicious               │
│ enrich_abuseipdb │ ✅      │ 14:32:17            │ Enriched with AbuseIPDB: score 85, 47 reports   │
│ enrich_geolocation│ ✅     │ 14:32:17            │ Enriched geolocation: Russia                    │
│ evaluate_decision│ ✅      │ 14:32:17            │ Decision: HIGH - INVESTIGATE                    │
└─────────────────┴─────────┴─────────────────────┴─────────────────────────────────────────────────┘

Report saved to reports/report_ALT-2024-001_20240115_143217.json
Run logged with ID: abc123
```

## API Reference

| API        | Data Provided                                   | Purpose                             | Score Impact |
| ---------- | ----------------------------------------------- | ----------------------------------- | ------------ |
| VirusTotal | Malware detection ratio, reputation             | Primary threat indicator            | 50% weight   |
| AbuseIPDB  | Abuse confidence, report history, TOR detection | Community-reported abuse data       | 35% weight   |
| ip-api.com | Geographic location, ISP info                   | Supporting context and risk factors | 15% weight   |

## Project Structure

```
alert-automation-engine/
├── engine/                 # Core automation logic
│   ├── alert_parser.py     # Alert normalization and validation
│   ├── enrichers/          # Threat intelligence APIs
│   │   ├── virustotal.py   # VirusTotal integration
│   │   ├── abuseipdb.py    # AbuseIPDB integration
│   │   └── geolocation.py  # IP geolocation service
│   ├── playbook.py         # Orchestration engine
│   ├── decision_engine.py  # Risk scoring and decisions
│   ├── reporter.py         # Output formatting
│   └── audit_logger.py     # Execution tracking
├── alerts/                 # Sample alert files
├── reports/                # Generated reports
├── tests/                  # Unit tests
├── main.py                 # CLI entry point
├── dataclasses.py          # Data models
├── requirements.txt        # Dependencies
├── .env.example            # Environment template
├── PLAYBOOK.md             # Detailed workflow docs
└── README.md               # This file
```

## Extending the Engine

### Adding a New Enricher

1. Create a new file in `engine/enrichers/`
2. Implement an enricher class with `enrich(ip: str) -> Result` method
3. Add error handling with custom exceptions
4. Update `dataclasses.py` with result model
5. Modify `playbook.py` to call the new enricher
6. Update `decision_engine.py` to incorporate the new data

Example:

```python
class NewEnricher:
    def enrich(self, ip: str) -> NewResult:
        # API call logic
        return NewResult(ip=ip, score=calculated_score)
```

### Adding a New Decision Rule

1. Modify `decision_engine.py`
2. Add new scoring logic in `evaluate()` method
3. Update composite score calculation
4. Add new threshold conditions
5. Update reasons list generation

Example:

```python
# Add new risk factor
new_risk = self._calculate_new_risk(new_result)
composite_score += new_risk * 0.10  # 10% weight

# Add to reasons
reasons.append(f"New factor: {new_risk} risk points")
```

This modular design allows the engine to evolve with new threat intelligence sources and decision criteria, mirroring how real SOAR platforms are extended in production environments.
