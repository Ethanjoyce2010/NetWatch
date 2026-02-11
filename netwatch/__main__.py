"""
NetWatch CLI — entry point for the network traffic anomaly detector.

Usage:
    python -m netwatch                      # live monitor (default 2s poll)
    python -m netwatch --interval 5         # poll every 5 seconds
    python -m netwatch --log alerts.json    # also write alerts to JSON file
    python -m netwatch --snapshot           # single snapshot + analysis then exit
    python -m netwatch --investigate 1234   # deep-dive into PID 1234
"""

from __future__ import annotations

import argparse
import logging
import signal
import sys
import time

from .detector import AnomalyDetector
from .dll_inspector import DLLInspector
from .investigator import ProcessInvestigator
from .monitor import TrafficMonitor
from .reporter import Reporter
from .threat_intel import ThreatIntelManager


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="netwatch",
        description="NetWatch — Network Traffic Anomaly Detector",
    )
    p.add_argument(
        "-i", "--interval",
        type=float,
        default=2.0,
        help="Seconds between polling snapshots (default: 2.0)",
    )
    p.add_argument(
        "--log",
        type=str,
        default=None,
        metavar="FILE",
        help="Write alerts to a JSON log file",
    )
    p.add_argument(
        "--snapshot",
        action="store_true",
        help="Take a single snapshot, analyse, and exit",
    )
    p.add_argument(
        "--investigate",
        type=int,
        default=None,
        metavar="PID",
        help="Deep-investigate a specific PID and exit",
    )
    p.add_argument(
        "--duration",
        type=int,
        default=0,
        metavar="SECONDS",
        help="Run for N seconds then print summary and exit (0 = indefinite)",
    )
    p.add_argument(
        "--min-risk",
        type=int,
        default=10,
        help="Minimum risk score to include in summary (default: 10)",
    )
    p.add_argument(
        "--dll-scan",
        action="store_true",
        help="Scan all running processes for injected / suspicious DLLs",
    )
    p.add_argument(
        "--dll-scan-pid",
        type=int,
        default=None,
        metavar="PID",
        help="Scan a specific PID for injected DLLs",
    )
    p.add_argument(
        "--update-feeds",
        action="store_true",
        help="Download / update threat intelligence feeds from abuse.ch",
    )
    p.add_argument(
        "--feed-status",
        action="store_true",
        help="Show status of threat intelligence feeds",
    )
    p.add_argument(
        "--api-key",
        type=str,
        default=None,
        metavar="KEY",
        help="abuse.ch API key for MalwareBazaar hash lookups",
    )
    p.add_argument(
        "--hash-lookup",
        type=str,
        default=None,
        metavar="SHA256",
        help="Look up a SHA256 hash in MalwareBazaar (requires --api-key)",
    )
    p.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable debug logging",
    )
    return p


BANNER = r"""
  _   _      ___          __   _       _     
 | \ | |    | \ \        / /  | |     | |    
 |  \| | ___| |\ \  /\  / /_ _| |_ ___| |__  
 | . ` |/ _ \ __\ \/  \/ / _` | __/ __| '_ \ 
 | |\  |  __/ |_ \  /\  / (_| | || (__| | | |
 |_| \_|\___|\__| \/  \/ \__,_|\__\___|_| |_|
                                             
  Network Traffic Anomaly Detector  v2.0.0
  Threat Intelligence Enhanced
"""


def main() -> None:
    args = _build_parser().parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )

    print(BANNER)

    # ---- Initialize threat intel ----
    threat_intel = ThreatIntelManager(api_key=args.api_key)

    # ---- Feed management modes ----
    if args.update_feeds:
        print("  Updating threat intelligence feeds...\n")
        statuses = threat_intel.update_feeds()
        for name, status in statuses.items():
            if status.error:
                print(f"  [FAIL] {status.description}")
                print(f"         Error: {status.error}")
            else:
                print(f"  [OK]   {status.description}")
                print(f"         {status.entry_count} entries loaded")
        print(f"\n  Feed cache: {threat_intel.cache_dir}")
        print(f"  Total C2 IPs loaded: {len(threat_intel.c2_ips)}")
        print(f"  Total malicious domains: {len(threat_intel.malicious_domains)}")
        print()
        return

    if args.feed_status:
        statuses = threat_intel.get_feed_status()
        print("  Threat Intelligence Feed Status:\n")
        for name, status in statuses.items():
            updated = status.last_updated.strftime("%Y-%m-%d %H:%M UTC") if status.last_updated else "never"
            print(f"  {name}:")
            print(f"    {status.description}")
            print(f"    Last updated: {updated}")
            if status.cache_path:
                from pathlib import Path
                exists = "yes" if Path(status.cache_path).exists() else "no"
                print(f"    Cache file: {status.cache_path} (exists: {exists})")
        print(f"\n  In-memory IOCs: {len(threat_intel.c2_ips)} C2 IPs, "
              f"{len(threat_intel.malicious_domains)} domains")
        if threat_intel.needs_update():
            print("  [!] Some feeds are stale or missing. Run --update-feeds to refresh.")
        print()
        return

    if args.hash_lookup:
        if not args.api_key and not threat_intel.api_key:
            print("  Error: --hash-lookup requires --api-key or ABUSE_CH_API_KEY env var.\n")
            return
        print(f"  Looking up hash: {args.hash_lookup}\n")
        match = threat_intel.lookup_hash_online(args.hash_lookup)
        if match:
            print(f"  [MATCH] {match.description}")
            if match.malware_family:
                info = threat_intel.get_malware_info(match.malware_family)
                if info:
                    print(f"  Family: {info}")
            if match.first_seen:
                print(f"  First seen: {match.first_seen}")
        else:
            print("  Hash not found in MalwareBazaar (clean or unknown).")
        print()
        return

    # ---- Auto-load feeds silently (if cached) ----
    if threat_intel.needs_update():
        print("  [i] Threat intel feeds not cached. Downloading...\n")
        threat_intel.update_feeds(quiet=True)
        print(f"  [i] Loaded {len(threat_intel.c2_ips)} C2 IPs, "
              f"{len(threat_intel.malicious_domains)} domains from feeds.\n")

    # ---- DLL scan mode ----
    if args.dll_scan or args.dll_scan_pid is not None:
        dll_inspector = DLLInspector(threat_intel=threat_intel)
        reporter = Reporter(log_file=args.log)
        if args.dll_scan_pid is not None:
            print(f"  Scanning PID {args.dll_scan_pid} for injected DLLs…\n")
            result = dll_inspector.scan_process(args.dll_scan_pid)
            if result:
                reporter.print_dll_scan([result])
            else:
                print(f"  Could not scan PID {args.dll_scan_pid} (not found or access denied).")
        else:
            print("  Scanning all processes for injected DLLs (this may take a moment)…\n")
            results = dll_inspector.scan_all()
            reporter.print_dll_scan(results)
        reporter.close()
        return

    # ---- Single PID investigation mode ----
    if args.investigate is not None:
        investigator = ProcessInvestigator()
        reporter = Reporter()
        inv = investigator.investigate(args.investigate)
        if inv:
            reporter.print_investigation(inv)
        else:
            print(f"  Could not find PID {args.investigate}.")
        return

    # ---- Monitor / snapshot mode ----
    monitor = TrafficMonitor(poll_interval=args.interval)
    detector = AnomalyDetector(threat_intel=threat_intel)
    reporter = Reporter(log_file=args.log)
    investigator = ProcessInvestigator()

    start_time = time.time()
    total_alerts = 0

    # Graceful shutdown
    running = True

    def _handle_signal(sig, frame):
        nonlocal running
        running = False
        print(f"\n\n  Caught signal {sig}, shutting down…")

    signal.signal(signal.SIGINT, _handle_signal)
    if hasattr(signal, "SIGTERM"):
        signal.signal(signal.SIGTERM, _handle_signal)

    if args.snapshot:
        # Single-shot mode
        print("  Taking snapshot…\n")
        records = monitor.snapshot()
        alerts = detector.analyse(records)
        total_alerts += len(alerts)
        reporter.report_alerts(alerts)
        risky = detector.get_risky_profiles(args.min_risk)
        reporter.print_summary(risky)
        for profile in risky[:5]:
            inv = investigator.investigate(profile.pid)
            if inv:
                reporter.print_investigation(inv)
        reporter.close()
        return

    # Continuous monitoring
    print(f"  Monitoring every {args.interval}s — press Ctrl+C to stop.\n")

    try:
        for records in monitor.stream():
            if not running:
                break

            alerts = detector.analyse(records)
            total_alerts += len(alerts)

            if alerts:
                print()  # newline before alerts
                reporter.report_alerts(alerts)

            elapsed = time.time() - start_time
            reporter.print_status(
                len(records), len(detector.profiles), total_alerts, elapsed
            )

            if args.duration and elapsed >= args.duration:
                running = False
    except KeyboardInterrupt:
        pass

    # Final summary
    risky = detector.get_risky_profiles(args.min_risk)
    reporter.print_summary(risky)

    if risky:
        print(f"  {len(risky)} suspicious process(es) — running deep investigations…\n")
        for profile in risky[:10]:
            inv = investigator.investigate(profile.pid)
            if inv:
                reporter.print_investigation(inv)

    reporter.close()
    print(f"  Done. {total_alerts} alert(s) raised during session.\n")


if __name__ == "__main__":
    main()
