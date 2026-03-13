# IPSniper
# 🛡️ IPSniper — Ultimate Cybersecurity Audit Platform

> A professional-grade, multi-protocol network scanner and vulnerability assessment platform built for security engineers, penetration testers, and red teamers.

---

## Overview

IPSniper started as a straightforward port scanner. It's now a full cybersecurity audit platform that handles everything from service fingerprinting and SSL/TLS analysis to CVE correlation, compliance checking, ML-based anomaly detection, and blockchain-backed audit trails — all from a single Python tool.

Built for authorized engagements only.

---

## Features

### Core Scanning
- **Multi-protocol scanning** — TCP, UDP support with concurrent threading (up to 200 threads by default)
- **Banner grabbing** — Extracts service banners for fingerprinting
- **OS fingerprinting** — TTL-based OS detection (Linux/Unix, Windows, Cisco/Network)
- **Hostname resolution** — Reverse DNS lookup per target
- **CIDR / range support** — Scan single IPs, ranges (`192.168.1.1-254`), or subnets (`/24`, `/16`)

### Vulnerability Intelligence
- **CVE correlation** — Matches banners against a built-in vuln DB (Apache, vsftpd, ProFTPD, Samba, OpenSSL, Exchange, Log4j, Spring4Shell, EternalBlue, and more)
- **CVSS scoring** — Every finding carries a CVSS score and exploit availability flag
- **MITRE ATT&CK mapping** — Vulnerabilities tagged with relevant technique IDs (T1190, T1133, T1110, etc.)
- **Default credential detection** — Checks FTP, SSH, Telnet, HTTP, MySQL, PostgreSQL, MongoDB, Redis
- **Lateral movement analysis** — Detects SMB→WinRM and SSH pivot paths automatically

### SSL/TLS Analysis
- Protocol version detection (flags SSLv3, TLSv1.0, TLSv1.1 as weak)
- Cipher suite inspection
- Certificate validity, expiry, and self-signed detection
- SAN list extraction
- RSA key size check with quantum-resistance flag (<4096-bit RSA flagged)

### Risk & Posture Scoring
- **Per-port risk score** (0–10) based on known vulns, exploit availability, SSL weakness, default creds
- **Per-host risk score** aggregated across all ports, compliance failures, anomalies, and threat intel hits
- **Security posture score** (0–100, higher is better) as an executive-facing metric
- **Attack surface area** — total open port count across the scan scope

### Threat Intelligence
- Pulls live blocklists from abuse.ch (Feodo, SSLBL), Emerging Threats, and Spamhaus DROP
- GeoIP enrichment via ip-api.com (country, city, ISP, ASN, timezone)
- Certificate Transparency log queries (crt.sh) for domain recon
- Per-IP threat score calculation (0–100)

### Compliance Checking
Automated checks mapped to:

| Framework | Controls Checked |
|-----------|-----------------|
| PCI-DSS   | Default creds, weak SSL, known vulns, unnecessary ports |
| HIPAA     | Encryption in transit, vulnerability management, access control |
| CIS       | Unnecessary services, open ports, firewall posture |
| GDPR      | Data protection, privacy by design |
| SOX       | Internal controls, audit trail |
| ISO 27001 | Vulnerability management, access control policy |

### ML Anomaly Detection
- `IsolationForest`-based anomaly detector trained on historical scan data
- Flags statistically abnormal hosts (unusual port counts, risk spikes, vuln surges)
- `RandomForestClassifier` available for vulnerability prediction

### Blockchain Audit Trail
- Every scan, login, and action appended to an in-memory blockchain
- Lightweight proof-of-work per block
- Chain integrity verification via `/api/blockchain/verify`
- Full audit trail export available

### Reporting
| Format | Description |
|--------|-------------|
| HTML   | Full interactive report with host cards, compliance tables, risk badges |
| JSON   | Machine-readable structured output |
| CSV    | Flat file for spreadsheet ingestion |
| XML    | Structured export for SIEM/SOAR parsing |
| SIEM   | NDJSON format, Splunk/ELK/QRadar compatible |

### Scan Diffing
Compare two scans to track changes: new hosts, closed/opened ports, risk score deltas.

### Notification Channels
- **Slack** — rich attachment format with severity colour coding
- **Microsoft Teams** — adaptive card format
- **Discord** — embed format
- **Generic webhook** — JSON POST to any endpoint
- **Email** — SMTP with STARTTLS
- **SMS** — Twilio/SNS stub (pluggable)
- **PagerDuty** — Events v2 API, critical severity only

### Cloud Integration
- **AWS** — EC2 instance discovery (running instances → auto-target)
- **Azure** — Resource Manager integration (subscription-scoped)
- **GCP** — Resource Manager client

### REST API & Web Dashboard
- Flask-based API with JWT authentication and rate limiting (Flask-Limiter)
- CORS enabled for cross-origin dashboard use
- React-ready JSON endpoints

---

## Installation

```bash
git clone https://github.com/yourhandle/ipsniper.git
cd ipsniper
pip install -r requirements.txt
```

### Minimum dependencies
```
colorama
tqdm
requests
```

### Full feature dependencies
```
flask flask-cors flask-limiter flask-jwt-extended werkzeug
psycopg2-binary          # PostgreSQL backend
pymongo                  # MongoDB backend
numpy scikit-learn       # ML anomaly detection
boto3                    # AWS integration
azure-identity azure-mgmt-resource  # Azure integration
google-cloud-resource-manager       # GCP integration
```

---

## Usage

### Basic scan
```bash
python ipsniper.py -t 192.168.1.1
```

### Subnet scan with HTML report
```bash
python ipsniper.py -t 192.168.1.0/24 -p common --report html -o report.html
```

### Custom port range
```bash
python ipsniper.py -t 10.10.10.5 -p 22,80,443,8080-8090
```

### Full port scan with UDP
```bash
python ipsniper.py -t 10.10.10.5 -p all --udp
```

### With compliance checking
```bash
python ipsniper.py -t 10.10.10.5 --compliance PCI-DSS,HIPAA,GDPR
```

### With threat intelligence feeds
```bash
python ipsniper.py -t 10.10.10.5 --threat-intel
```

### With ML anomaly detection
```bash
python ipsniper.py -t 192.168.1.0/24 --ml --report html -o scan.html
```

### Scan diffing (compare against baseline)
```bash
python ipsniper.py -t 192.168.1.0/24 --compare baseline.json
```

### Slack alert on critical findings
```bash
python ipsniper.py -t 10.10.10.5 --webhook https://hooks.slack.com/services/xxx
```

### CI/CD pipeline mode (non-zero exit on critical vulns)
```bash
python ipsniper.py -t 10.10.10.5 --exit-code
```

### Start REST API + web dashboard
```bash
python ipsniper.py --api --api-port 5000
```

### AWS cloud target discovery
```bash
python ipsniper.py --cloud aws -p common --report json -o aws_scan.json
```

### Azure with subscription
```bash
python ipsniper.py --cloud azure --azure-subscription <subscription-id>
```

---

## CLI Reference

```
-t, --target            Target IP, CIDR, or range (e.g. 192.168.1.0/24)
-p, --ports             Port list: 'common', 'all', or '22,80,443,8080-9090'
    --protocols         tcp | udp | both
    --threads           Thread count (default: 200)
    --timeout           Connection timeout in seconds (default: 2.0)
    --udp               Include UDP scanning
    --compliance        Comma-separated frameworks: PCI-DSS,HIPAA,GDPR,SOX,ISO27001
    --threat-intel      Pull live threat intelligence feeds
    --ml                Enable ML anomaly detection
    --report            html | json | csv | xml | siem
-o, --output            Output file path
-v, --verbose           Debug logging
    --db                SQLite DB path (default: ultimate_scanner.db)
    --db-type           sqlite | postgres | mongodb
    --db-uri            Database connection URI
    --api               Start REST API mode
    --api-port          API port (default: 5000)
    --webhook           Webhook URL (repeatable)
    --email-smtp        SMTP server hostname
    --email-from        Sender email address
    --email-to          Recipient email (repeatable)
    --compare           Path to previous scan JSON for diffing
    --cloud             aws | azure | gcp
    --azure-subscription  Azure subscription ID
    --gcp-project       GCP project ID
    --exit-code         Exit 1 if critical vulns found (CI/CD use)
```

---

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET`  | `/` | Web dashboard |
| `POST` | `/api/scan` | Start a scan (`{"target": "...", "ports": "common"}`) |
| `GET`  | `/api/results` | Last 100 host results |
| `GET`  | `/api/history` | Last 10 scan records |
| `GET`  | `/api/trends?days=30` | Risk trend data over N days |
| `GET`  | `/api/export/<format>` | Export results (`html`, `json`, `siem`) |
| `GET`  | `/api/blockchain/verify` | Verify audit chain integrity |

Rate limited to 10 scans/minute per IP. JWT auth supported.

---

## Database Backends

| Backend | Flag | Notes |
|---------|------|-------|
| SQLite  | `--db-type sqlite` | Default, no setup required |
| PostgreSQL | `--db-type postgres --db-uri postgresql://...` | Production use |
| MongoDB | `--db-type mongodb --db-uri mongodb://...` | Schema-less, aggregation pipelines |

Schema covers: `scans`, `hosts`, `ports`, `vulnerabilities`, `compliance`, `audit_log`, `scan_profiles`, `ml_models`, `network_topology`.

---

## Risk Scoring Reference

| Score Range | Level    |
|-------------|----------|
| 8.0 – 10.0  | CRITICAL |
| 6.0 – 7.9   | HIGH     |
| 4.0 – 5.9   | MEDIUM   |
| 2.0 – 3.9   | LOW      |
| 0.0 – 1.9   | INFO     |

Score factors: open port base risk, CVSS × exploit multiplier, weak SSL, expired/self-signed cert, default credentials found, threat intel hit, compliance failures, detected anomalies, lateral movement paths.

---

## Asset Auto-Categorization

IPSniper automatically classifies hosts by the services it finds:

| Category | Ports |
|----------|-------|
| web_server | 80, 443, 8080, 8443 |
| database | 3306, 5432, 1433, 27017, 6379, 1521 |
| mail_server | 25, 110, 143, 465, 587, 993, 995 |
| file_server | 21, 22, 139, 445 |
| directory_service | 389, 636, 88, 3268 |
| network_device | 22, 23, 161, 162, 179 |
| iot_device | 1883, 8883, 5683, 5684 |
| kubernetes | 6443, 10250, 2379 |
| monitoring | 9090, 9093, 3000, 8086 |

---

## Legal

For authorized use only. Run this tool exclusively against systems you own or have explicit written permission to test. Unauthorized scanning is illegal under the Computer Fraud and Abuse Act (CFAA), the Computer Misuse Act (CMA), and equivalent laws in most jurisdictions.

---
