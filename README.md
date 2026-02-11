# NetWatch — Network Traffic Anomaly Detector

A Python tool that monitors live network connections, detects suspicious behaviour, and narrows down potentially malicious processes.

## Features

| Capability | Details |
|---|---|
| **Live monitoring** | Polls OS network connections at a configurable interval |
| **Process mapping** | Maps every connection to its owning process (name, PID, exe, user) |
| **9 detection rules** | Suspicious ports, unexpected network processes, high connection rates, IP/port scanning, Tor usage, DNS tunnelling indicators, external listeners, C2-style callbacks |
| **Risk scoring** | Each process accumulates a 0–100 risk score based on triggered alerts |
| **Deep investigation** | Drills into flagged processes — parent/child tree, open files, env vars, fileless-malware check |
| **JSON alerting** | Optionally writes structured alerts to a JSON file for SIEM ingestion |
| **Coloured output** | Severity-coded terminal output for quick triage |

## Requirements

- Python 3.10+
- `psutil` (the only dependency)
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

# Single snapshot — analyse and exit immediately
python -m netwatch --snapshot

# Write alerts to a JSON log file
python -m netwatch --log alerts.json

# Deep-investigate a specific PID
python -m netwatch --investigate 1234

# Verbose debug output
python -m netwatch -v
```

## Detection Rules

| # | Rule | Severity | What it catches |
|---|---|---|---|
| 1 | **Suspicious Port** | HIGH | Connection to known malware/C2/mining ports (4444, 6667, 3333, 31337 …) |
| 2 | **Unexpected Network Process** | CRITICAL | Programs like `notepad.exe` or `calc.exe` making network calls |
| 3 | **High Connection Rate** | MEDIUM | >50 connections in 60s (beaconing / DDoS) |
| 4 | **IP Scan Detected** | HIGH | Process contacts ≥25 unique IPs |
| 5 | **Port Scan Detected** | HIGH | Process connects to ≥15 unique remote ports |
| 6 | **Tor Network Usage** | MEDIUM | Tor process or SOCKS port 9050/9150 |
| 7 | **Non-standard DNS Port** | MEDIUM | DNS process using ports other than 53/853/5353 |
| 8 | **External Listener** | MEDIUM | Process listening on 0.0.0.0 or public IP on unusual port |
| 9 | **External High-Port Connection** | LOW | Established connection to external host on ephemeral port |

## Output Example

```
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

```
netwatch/
├── __init__.py        # Package metadata
├── __main__.py        # CLI entry point
├── models.py          # Data classes (ConnectionRecord, Alert, ProcessProfile)
├── monitor.py         # TrafficMonitor — polls psutil for connections
├── detector.py        # AnomalyDetector — 9 heuristic detection rules
├── investigator.py    # ProcessInvestigator — deep forensic dump
└── reporter.py        # Reporter — coloured console + JSON output
```

## Notes

- This is a **host-based** monitor — it sees connections from the machine it runs on, not raw packet captures. For full packet-level inspection, pair it with a tool like Wireshark or Zeek.
- Run with **elevated privileges** (`Run as Administrator` on Windows, `sudo` on Linux/macOS) for accurate process-to-connection mapping.
- The detection rules are heuristic — tune thresholds in the `AnomalyDetector` constructor for your environment.
- Alerts are de-duplicated per-session so the same issue doesn't spam the console.
