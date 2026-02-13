# NetWatch — Network Traffic Anomaly Detector

A Python tool that monitors live network connections, detects suspicious behaviour, cross-references against live threat intelligence feeds, and narrows down potentially malicious processes.

## Features

| Capability | Details |
| --- | --- |
| **Live monitoring** | Polls OS network connections at a configurable interval |
| **Process mapping** | Maps every connection to its owning process (name, PID, exe, user) |
| **14 detection rules** | Suspicious ports, unexpected processes, high connection rates, IP/port scanning, Tor, DNS tunnelling, external listeners, C2 callbacks, **known C2 IPs, beaconing, process masquerading, DNS exfiltration, crypto mining** |
| **Threat intelligence feeds** | Auto-downloads IOC feeds from abuse.ch (Feodo Tracker, SSLBL, URLhaus) — C2 IPs, malicious domains, malware URLs |
| **MalwareBazaar integration** | Optional SHA256 hash lookups against MalwareBazaar API (free auth key) |
| **DLL injection detection** | 8 heuristics including hash verification against threat intel |
| **PDF report generator** | `--pdf report.pdf` creates a multi-page report with executive summary, network stats, alert tables, investigations, feed status, and a prioritised **Recommended Actions** section |
| **Network statistics** | `--stats` shows protocol breakdown, traffic direction, top remote IPs, top processes, connection states |
| **Top talkers** | `--top N` ranks the busiest processes by connection count |
| **Process whitelist** | Suppress known-good alerts via `whitelist.json` (e.g. svchost.exe External Listener noise) |
| **CSV export** | `--export-csv` / `--export-connections-csv` for spreadsheet or SIEM analysis |
| **Smart listener filter** | Known Windows services auto-excluded from External Listener alerts |
| **80+ known malware DLL names** | Extended definitions covering Cobalt Strike, Metasploit, Mimikatz, RATs, stealers, loaders, APT tools |
| **30+ malware family database** | Built-in descriptions for Emotet, TrickBot, QakBot, Cobalt Strike, RedLine, Lumma, and more |
| **Process masquerade detection** | Validates critical Windows processes run from expected directories |
| **LOLBin detection** | Flags Living Off the Land Binaries making external connections |
| **DGA domain detection** | Regex patterns to catch algorithmically generated domain names |
| **Risk scoring** | Each process accumulates a 0-100 risk score based on triggered alerts |
| **Deep investigation** | Drills into flagged processes - parent/child tree, open files, env vars, fileless-malware check |
| **JSON alerting** | Optionally writes structured alerts to a JSON file for SIEM ingestion |
| **Coloured output** | Severity-coded terminal output for quick triage |
| **Interactive batch menu** | Windows batch file UI with 14 menu options |

## Requirements

- Python 3.10+
- `psutil`
- `fpdf2` (for PDF report generation)
- **Administrator / root** privileges (required to read connection-to-process mappings)

## Installation

```bash
pip install -r requirements.txt
```

## Usage

```bash
# Run as Administrator / root for full visibility

# Live monitor (polls every 2 seconds, Ctrl+C to stop and see summary)
python -m netwatch

# Custom poll interval
python -m netwatch --interval 5

# Run for 60 seconds then auto-summarise
python -m netwatch --duration 60

# Single snapshot - analyse and exit immediately
python -m netwatch --snapshot

# Generate a PDF report (works with --snapshot or --dll-scan)
python -m netwatch --snapshot --pdf report.pdf
python -m netwatch --dll-scan --pdf dll_report.pdf

# Write alerts to a JSON log file
python -m netwatch --log alerts.json

# Deep-investigate a specific PID
python -m netwatch --investigate 1234

# Scan all processes for injected DLLs
python -m netwatch --dll-scan

# Scan a specific PID for DLL injection
python -m netwatch --dll-scan-pid 1234

# Update threat intelligence feeds (Feodo Tracker, SSLBL, URLhaus)
python -m netwatch --update-feeds

# Show feed status and cached IOC counts
python -m netwatch --feed-status

# Look up a SHA256 hash in MalwareBazaar (requires free API key)
python -m netwatch --hash-lookup <SHA256> --api-key <YOUR_KEY>

# Verbose debug output
python -m netwatch -v

# Show network statistics summary
python -m netwatch --snapshot --stats

# Show top 15 processes by connection count + stats
python -m netwatch --snapshot --top 15 --stats

# Export alerts and connections to CSV
python -m netwatch --snapshot --export-csv alerts.csv --export-connections-csv conns.csv

# Use a custom whitelist file
python -m netwatch --snapshot --whitelist my_whitelist.json

# Full combo: snapshot + stats + PDF + CSV
python -m netwatch --snapshot --stats --pdf report.pdf --export-csv alerts.csv
```

## Detection Rules

| # | Rule | Severity | What it catches |
| --- | --- | --- | --- |
| 1 | **Suspicious Port** | HIGH | Connection to known malware/C2/mining ports (4444, 6667, 3333, 31337 ...) |
| 2 | **Unexpected Network Process** | CRITICAL | Programs like `notepad.exe`, `calc.exe`, or LOLBins making network calls |
| 3 | **High Connection Rate** | MEDIUM | >80 connections in 60s (beaconing / DDoS) |
| 4 | **IP Scan Detected** | HIGH | Process contacts >=30 unique IPs |
| 5 | **Port Scan Detected** | HIGH | Process connects to >=20 unique remote ports |
| 6 | **Tor Network Usage** | MEDIUM | Tor process or SOCKS port 9050/9150 |
| 7 | **Non-standard DNS Port** | MEDIUM | DNS process using ports other than 53/853/5353 |
| 8 | **External Listener** | MEDIUM | Process listening on 0.0.0.0 or public IP on unusual port |
| 9 | **External High-Port Connection** | LOW | Established connection to external host on ephemeral port |
| 10 | **Known C2 IP (Threat Intel)** | CRITICAL | Connection to IP in abuse.ch C2 blocklists (Feodo, SSLBL, URLhaus) |
| 11 | **Beaconing Detected** | HIGH | Regular-interval connections to same destination (C2 callback pattern) |
| 12 | **Process Masquerading / LOLBin** | CRITICAL/HIGH | Critical process running from wrong directory, or LOLBin with outbound connections |
| 13 | **DNS Exfiltration Suspect** | MEDIUM | Non-DNS process directly querying external DNS servers |
| 14 | **Crypto Mining Detected** | HIGH | Connection to known mining pool ports on external IPs |

## Threat Intelligence Feeds

NetWatch auto-downloads and caches IOC feeds from [abuse.ch](https://abuse.ch) (free, no API key required):

| Feed | Source | Data |
| --- | --- | --- |
| **Feodo Tracker** | feodotracker.abuse.ch | Botnet C2 IPs (Emotet, TrickBot, QakBot, Dridex) |
| **SSLBL** | sslbl.abuse.ch | SSL-based C2 IP blacklist |
| **URLhaus** | urlhaus.abuse.ch | Active malware distribution URLs, IPs, domains |

Feeds are cached locally (~1 hour expiry) and loaded automatically on startup. Run `--update-feeds` to force a refresh.

Note: the downloaded feed cache files and generated `*.pdf` reports are ignored by git (see `.gitignore`).

For enhanced hash lookups, get a free API key at [auth.abuse.ch](https://auth.abuse.ch/) and use `--api-key` or set the `ABUSE_CH_API_KEY` environment variable.

## Output Example

```bash
  ⚠ [CRITICAL] Unexpected Network Process — PID 9128 (notepad.exe): should not be making network connections
  ⚠ [HIGH] Suspicious Port — PID 4412 (svchost.exe): Connection to suspicious port 4444 on 203.0.113.50

================================================================================
  SUSPICIOUS PROCESS SUMMARY (sorted by risk)
================================================================================
  PID      Name                    Risk  Alerts    IPs  Ports  User
  --------------------------------------------------------------------------
  9128     notepad.exe               50       1      1      1  DESKTOP\user
  4412     svchost.exe               30       1      1      1  NT AUTHORITY\SYSTEM
================================================================================
```

## Architecture

```bash
netwatch/
├── __init__.py        # Package metadata (v2.3.0)
├── __main__.py        # CLI entry point (monitor/snapshot/investigate/DLL scan/PDF)
├── models.py          # Data classes (ConnectionRecord, Alert, ProcessProfile)
├── monitor.py         # TrafficMonitor - polls psutil for connections
├── detector.py        # AnomalyDetector - 14 heuristic detection rules
├── threat_intel.py    # ThreatIntelManager - IOC feed downloads, caching, lookups
├── dll_inspector.py   # DLLInspector - 8 DLL injection heuristics + hash check
├── investigator.py    # ProcessInvestigator - deep forensic dump
├── pdf_report.py      # PDFReportGenerator - multi-page report output
├── reporter.py        # Reporter - coloured console + JSON output
├── stats.py           # NetworkStats - protocol/traffic/top-talker analysis
├── whitelist.py       # ProcessWhitelist - suppress known-good process alerts
└── csv_export.py      # CSV exporter for alerts and connection records
```

## Notes

- This is a **host-based** monitor — it sees connections from the machine it runs on, not raw packet captures. For full packet-level inspection, pair it with a tool like Wireshark or Zeek.
- Run with **elevated privileges** (`Run as Administrator` on Windows, `sudo` on Linux/macOS) for accurate process-to-connection mapping.
- The detection rules are heuristic — tune thresholds in the `AnomalyDetector` constructor for your environment.
- Alerts are de-duplicated per-session so the same issue doesn't spam the console.
