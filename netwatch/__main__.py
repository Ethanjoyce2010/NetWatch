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
        "-v", "--verbose",
        action="store_true",
        help="Enable debug logging",
    )
    return p


BANNER = r"""
  _   _      _ __        __    _       _
 | \ | | ___| |\ \      / /_ _| |_ ___| |__
 |  \| |/ _ \ __\ \ /\ / / _` | __/ __| '_ \
 | |\  |  __/ |_ \ V  V / (_| | || (__| | | |
 |_| \_|\___|\__| \_/\_/ \__,_|\__\___|_| |_|

  Network Traffic Anomaly Detector  v1.0.0
"""


def main() -> None:
    args = _build_parser().parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )

    print(BANNER)

    # ---- DLL scan mode ----
    if args.dll_scan or args.dll_scan_pid is not None:
        dll_inspector = DLLInspector()
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
    detector = AnomalyDetector()
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
