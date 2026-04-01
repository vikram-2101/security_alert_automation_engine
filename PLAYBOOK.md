# Security Alert Automation Playbook

## Overview

This playbook automates the initial triage and response to security alerts in a Security Operations Center (SOC) environment. It transforms a manual, time-intensive process that typically takes 10-15 minutes per alert into an automated workflow completing in under 5 seconds.

## Manual Process (Before Automation)

When a security alert fires (e.g., "suspicious login from unknown IP"), SOC analysts manually:

1. **Extract IP Address**: Copy the IP from the alert
2. **VirusTotal Check**: Open browser, paste IP, review malware analysis results
3. **AbuseIPDB Check**: Query reputation database for abuse reports
4. **Geolocation Lookup**: Determine geographic origin of the IP
5. **Risk Assessment**: Evaluate combined threat intelligence
6. **Decision Making**: Determine severity level and appropriate response
7. **Documentation**: Write summary and take action (block/escalate/monitor)

## Automated Playbook Workflow

### Step 1: Alert Parsing

- **Input**: Raw alert data (JSON format)
- **Processing**:
  - Validate alert structure
  - Extract or identify IP address
  - Reject private IPs (RFC 1918, link-local)
  - Parse timestamp and metadata
- **Output**: Structured Alert object

### Step 2: Intelligence Enrichment

#### VirusTotal Integration

- **API**: GET /api/v3/ip_addresses/{ip}
- **Data Retrieved**:
  - Malware detection ratio (malicious/total engines)
  - Last analysis timestamp
  - Reputation classification
- **Weight**: 40% in composite score

#### AbuseIPDB Integration

- **API**: GET /api/v2/check with ipAddress parameter
- **Data Retrieved**:
  - Abuse confidence score (0-100)
  - Total abuse reports
  - Last reported timestamp
  - Geographic location
- **Weight**: 40% in composite score

#### Geolocation Enrichment

- **API**: ip-api.com (free tier, no authentication)
- **Data Retrieved**:
  - Country, city, coordinates
  - ISP information
- **Processing**:
  - High-risk country penalty (+0.3 to score)
  - TOR network detection override
- **Weight**: 20% in composite score

### Step 3: Risk Scoring and Decision Engine

#### Composite Score Calculation

```
composite_score = (vt_malware_ratio × 0.4) + (abuse_score/100 × 0.4) + (geo_score × 0.2)
```

#### Geographic Risk Assessment

- **High-Risk Countries**: North Korea, Iran, Russia, China
- **Penalty**: +0.3 to total score
- **TOR Override**: Any IP with TOR ISP → High severity, Block action

#### Decision Thresholds

- **Low Risk** (< 0.3): Monitor only
- **Medium Risk** (0.3 - 0.7): Escalate to analyst
- **High Risk** (> 0.7): Immediate blocking

#### Confidence Levels

- Low: 0.4 (minimal enrichment data)
- Medium: 0.6 (partial enrichment success)
- High: 0.8+ (full enrichment pipeline)

### Step 4: Automated Actions

#### Monitor

- Log alert for review
- No immediate action
- Suitable for low-confidence or low-risk alerts

#### Escalate

- Flag for human analyst review
- Include detailed enrichment summary
- Analyst can override automated decision

#### Block

- Immediate IP blocking at network perimeter
- High-confidence, high-risk indicators
- Automatic firewall rule creation

### Step 5: Reporting and Audit

#### Terminal Report

- Rich-formatted output with tables
- Color-coded severity levels
- Step-by-step execution timeline
- Detailed reasoning for decisions

#### JSON Report Archive

- Structured data for SIEM integration
- Historical analysis capabilities
- Compliance reporting

#### Audit Logging

- SQLite database for all executions
- API call metrics and performance
- Success/failure tracking
- Statistical reporting

## Error Handling and Resilience

### Enrichment Failures

- **Strategy**: Continue processing with neutral scores
- **Fallback**: Use default values (0 risk) rather than abort
- **Logging**: Record failures without impacting workflow

### Parsing Failures

- **Strategy**: Abort playbook execution
- **Reasoning**: Invalid alerts cannot be processed safely

### Decision Failures

- **Strategy**: Abort with safe default (monitor)
- **Reasoning**: Risk assessment is critical for automation

### API Rate Limits

- **Strategy**: Exponential backoff retry (up to 3 attempts)
- **Limits**: Respect API provider constraints

## Configuration and Deployment

### Environment Variables

```
VIRUSTOTAL_API_KEY=your_api_key
ABUSEIPDB_API_KEY=your_api_key
```

### CLI Commands

- `python main.py run <alert_file>`: Execute playbook
- `python main.py stats`: View audit statistics
- `python main.py history`: Recent execution history
- `python main.py test-apis`: Validate API integrations

## Benefits and Metrics

### Efficiency Gains

- **Time Reduction**: 10-15 minutes → <5 seconds per alert
- **Scalability**: Handle hundreds of alerts simultaneously
- **Consistency**: Standardized risk assessment

### Quality Improvements

- **Comprehensive Enrichment**: Multiple intelligence sources
- **Bias Reduction**: Algorithmic scoring minimizes human error
- **Audit Trail**: Complete execution history

### SOC Integration

- **SIEM Compatible**: JSON output for log aggregation
- **Playbook Extensible**: Modular design for additional enrichments
- **Human Override**: Analyst can review and modify decisions

## Future Enhancements

- Additional enrichment sources (Shodan, WHOIS, passive DNS)
- Machine learning risk scoring
- Integration with SOAR platforms
- Automated remediation workflows
- Threat intelligence sharing

---

_This playbook represents a production-ready implementation of automated security alert triage, suitable for deployment in enterprise SOC environments._
