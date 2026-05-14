"""
NetWatch CLI - entry point for the network traffic anomaly detector.

Usage:
    python -m netwatch                      # live monitor (default 2s poll)
    python -m netwatch --snapshot           # single snapshot + analysis
    python -m netwatch --snapshot --pdf report.pdf
    python -m netwatch --dll-scan           # scan all processes for injected DLLs
    python -m netwatch --update-feeds       # download threat intel feeds
    python -m netwatch --feed-status        # show feed info
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
from .html_report import HTMLReportGenerator
from .reporter import Reporter
from .threat_intel import ThreatIntelManager
from .whitelist import ProcessWhitelist
from .stats import compute_stats, print_stats
from .csv_export import export_alerts_csv, export_connections_csv
from .config import load_config
from .geoip import GeoIPEnricher
from .notifier import Notifier
from .learning import LearningWhitelistBuilder
from .response import ProcessResponder
from .scheduler import TaskSchedulerScanner
from .network_map import NetworkMapGenerator


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
        "--otx-api-key",
        type=str,
        default=None,
        metavar="KEY",
        help="AlienVault OTX API key for pulse import or indicator lookup",
    )
    p.add_argument(
        "--otx-lookup",
        type=str,
        default=None,
        metavar="INDICATOR",
        help="Look up an IP, domain, or hash in AlienVault OTX",
    )
    p.add_argument(
        "--update-otx-pulses",
        action="store_true",
        help="Import indicators from subscribed AlienVault OTX pulses",
    )
    p.add_argument(
        "--vt-api-key",
        type=str,
        default=None,
        metavar="KEY",
        help="VirusTotal API key for indicator lookups",
    )
    p.add_argument(
        "--vt-lookup",
        type=str,
        default=None,
        metavar="INDICATOR",
        help="Look up an IP, domain, or hash in VirusTotal",
    )
    p.add_argument(
        "--pdf",
        type=str,
        default=None,
        metavar="FILE",
        help="Generate a PDF report (combine with --snapshot or --dll-scan)",
    )
    p.add_argument(
        "--export-csv",
        type=str,
        default=None,
        metavar="FILE",
        help="Export alerts to CSV file",
    )
    p.add_argument(
        "--export-connections-csv",
        type=str,
        default=None,
        metavar="FILE",
        help="Export raw connection records to CSV file",
    )
    p.add_argument(
        "--html",
        type=str,
        default=None,
        metavar="FILE",
        help="Generate an HTML report (combine with --snapshot or --dll-scan)",
    )
    p.add_argument(
        "--network-map",
        type=str,
        default=None,
        metavar="FILE",
        help="Generate an HTML process-to-endpoint network map",
    )
    p.add_argument(
        "--live-map",
        type=str,
        default=None,
        metavar="FILE",
        help="Update an auto-refreshing HTML network map during live monitoring",
    )
    p.add_argument(
        "--map-refresh",
        type=int,
        default=3,
        metavar="SECONDS",
        help="Browser refresh interval for --live-map output (default: 3)",
    )
    p.add_argument(
        "--config",
        type=str,
        default=None,
        metavar="FILE",
        help="Path to netwatch.toml configuration file",
    )
    p.add_argument(
        "--discord-webhook",
        type=str,
        default=None,
        metavar="URL",
        help="Discord webhook URL for real-time notifications",
    )
    p.add_argument(
        "--slack-webhook",
        type=str,
        default=None,
        metavar="URL",
        help="Slack webhook URL for real-time notifications",
    )
    p.add_argument(
        "--notify-min-severity",
        type=str,
        default=None,
        choices=["LOW", "MEDIUM", "HIGH", "CRITICAL"],
        help="Minimum severity to trigger notifications (default: HIGH)",
    )
    p.add_argument(
        "--geoip-db",
        type=str,
        default=None,
        metavar="PATH",
        help="Path to GeoLite2 database file or directory",
    )
    p.add_argument(
        "--top",
        type=int,
        default=None,
        nargs="?",
        const=10,
        metavar="N",
        help="Show top-N processes by connection count (default: 10)",
    )
    p.add_argument(
        "--stats",
        action="store_true",
        help="Show network statistics summary after snapshot/monitoring",
    )
    p.add_argument(
        "--whitelist",
        type=str,
        default=None,
        metavar="FILE",
        help="Path to a whitelist.json for suppressing known-good alerts",
    )
    p.add_argument(
        "--learning-mode",
        type=str,
        default=None,
        metavar="FILE",
        help="Observe normal activity and write learned whitelist suggestions to FILE",
    )
    p.add_argument(
        "--learn-duration",
        type=int,
        default=30,
        metavar="SECONDS",
        help="Seconds to observe when using --learning-mode (default: 30)",
    )
    p.add_argument(
        "--learn-min-count",
        type=int,
        default=1,
        metavar="N",
        help="Minimum repeated alert count before learning a whitelist entry",
    )
    p.add_argument(
        "--kill-critical",
        action="store_true",
        help="Prompt to terminate processes that trigger CRITICAL alerts",
    )
    p.add_argument(
        "--quarantine-critical",
        type=str,
        default=None,
        nargs="?",
        const="",
        metavar="DIR",
        help="Prompt to move executables for CRITICAL alerts into quarantine",
    )
    p.add_argument(
        "--task-scan",
        action="store_true",
        help="Scan Windows scheduled tasks for persistence indicators and exit",
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
                                             
  Network Traffic Anomaly Detector  v3.0.0
  Threat Intelligence Enhanced | GeoIP | Notifications
"""


def _print_ioc_match(match) -> None:
    """Print an IOC provider match in a consistent CLI format."""
    if not match:
        print("  Indicator not found or no malicious reputation reported.\n")
        return
    print(f"  [MATCH] {match.description or match.source}")
    print(f"  Source: {match.source}")
    print(f"  Type: {match.indicator_type}")
    print(f"  Confidence: {match.confidence}")
    if match.malware_family:
        print(f"  Family/label: {match.malware_family}")
    if match.first_seen:
        print(f"  First seen: {match.first_seen}")
    print()


def main() -> None:
    args = _build_parser().parse_args()

    # Ensure stdout can handle Unicode on Windows terminals
    if sys.stdout.encoding and sys.stdout.encoding.lower() not in ("utf-8", "utf8"):
        try:
            if hasattr(sys.stdout, "reconfigure"):
                sys.stdout.reconfigure(errors="replace")  # type: ignore[union-attr]
            if hasattr(sys.stderr, "reconfigure"):
                sys.stderr.reconfigure(errors="replace")  # type: ignore[union-attr]
        except Exception:
            pass

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )

    print(BANNER)

    # ---- Load configuration ----
    cfg = load_config(args.config)

    # CLI overrides for config values
    if args.interval != 2.0:
        cfg.monitor.poll_interval = args.interval
    if args.duration != 0:
        cfg.monitor.duration = args.duration
    if args.min_risk != 10:
        cfg.detector.min_risk_score = args.min_risk
    if args.api_key:
        cfg.feeds.api_key = args.api_key
    if args.discord_webhook:
        cfg.notifications.discord_webhook = args.discord_webhook
    if args.slack_webhook:
        cfg.notifications.slack_webhook = args.slack_webhook
    if args.notify_min_severity:
        cfg.notifications.min_severity = args.notify_min_severity
    if args.geoip_db:
        cfg.geoip.db_path = args.geoip_db
    if args.pdf:
        cfg.reporting.pdf_output = args.pdf
    if args.html:
        cfg.reporting.html_output = args.html

    # ---- Initialize threat intel ----
    threat_intel = ThreatIntelManager(api_key=cfg.feeds.api_key or args.api_key)

    # ---- Initialize whitelist ----
    whitelist = ProcessWhitelist(path=args.whitelist)
    if whitelist.loaded:
        print(f"  {whitelist.summary()}\n")

    # ---- Initialize GeoIP enricher ----
    geoip = GeoIPEnricher(db_path=cfg.geoip.db_path or None)
    if geoip.available:
        print("  [+] GeoIP enrichment enabled.\n")

    # ---- Initialize notifier ----
    notifier = Notifier(
        discord_webhook=cfg.notifications.discord_webhook,
        slack_webhook=cfg.notifications.slack_webhook,
        email_to=cfg.notifications.email_to,
        email_smtp=cfg.notifications.email_smtp,
        email_port=cfg.notifications.email_port,
        email_user=cfg.notifications.email_user,
        email_password=cfg.notifications.email_password,
        email_from=cfg.notifications.email_from,
        min_severity=cfg.notifications.min_severity,
        cooldown_seconds=cfg.notifications.cooldown_seconds,
    )
    if notifier.enabled:
        channels = []
        if cfg.notifications.discord_webhook:
            channels.append("Discord")
        if cfg.notifications.slack_webhook:
            channels.append("Slack")
        if cfg.notifications.email_to:
            channels.append("Email")
        print(f"  [+] Notifications enabled: {', '.join(channels)}\n")

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

    if args.update_otx_pulses:
        if not args.otx_api_key and not threat_intel.otx_api_key:
            print("  Error: --update-otx-pulses requires --otx-api-key or OTX_API_KEY env var.\n")
            return
        print("  Updating AlienVault OTX subscribed pulses...\n")
        status = threat_intel.update_otx_pulses(api_key=args.otx_api_key)
        if status.error:
            print(f"  [FAIL] {status.description}")
            print(f"         Error: {status.error}")
        else:
            print(f"  [OK]   {status.description}")
            print(f"         {status.entry_count} indicators loaded")
        print()
        return

    if args.otx_lookup:
        if not args.otx_api_key and not threat_intel.otx_api_key:
            print("  Error: --otx-lookup requires --otx-api-key or OTX_API_KEY env var.\n")
            return
        print(f"  Looking up OTX indicator: {args.otx_lookup}\n")
        match = threat_intel.lookup_otx_indicator(args.otx_lookup, api_key=args.otx_api_key)
        _print_ioc_match(match)
        return

    if args.vt_lookup:
        if not args.vt_api_key and not threat_intel.virustotal_api_key:
            print("  Error: --vt-lookup requires --vt-api-key or VIRUSTOTAL_API_KEY env var.\n")
            return
        print(f"  Looking up VirusTotal indicator: {args.vt_lookup}\n")
        match = threat_intel.lookup_virustotal_indicator(args.vt_lookup, api_key=args.vt_api_key)
        _print_ioc_match(match)
        return

    if args.task_scan and not args.snapshot and not args.duration and not args.network_map and not args.live_map:
        print("  Scanning scheduled tasks for persistence indicators...\n")
        scanner = TaskSchedulerScanner()
        findings = scanner.scan()
        Reporter().print_task_scan(findings)
        _maybe_pdf(task_findings=findings)
        _maybe_html(task_findings=findings)
        return

    if args.learning_mode:
        monitor = TrafficMonitor(poll_interval=cfg.monitor.poll_interval)
        detector = AnomalyDetector(
            threat_intel=threat_intel,
            whitelist=whitelist,
            connection_rate_threshold=cfg.detector.connection_rate_threshold,
            rate_window_seconds=cfg.detector.rate_window_seconds,
            min_unique_ips_for_scan_alert=cfg.detector.min_unique_ips_for_scan_alert,
            port_scan_unique_ports=cfg.detector.port_scan_unique_ports,
        )

        duration = max(0, args.learn_duration)
        all_alerts = []
        print(
            f"  Learning mode: observing for "
            f"{duration}s and writing suggestions to {args.learning_mode}\n"
        )
        end_time = time.time() + duration
        while True:
            records = monitor.snapshot()
            for rec in records:
                geoip.enrich_record(rec)
            all_alerts.extend(detector.analyse(records))
            if duration == 0 or time.time() >= end_time:
                break
            time.sleep(cfg.monitor.poll_interval)

        learner = LearningWhitelistBuilder()
        learned = learner.build(all_alerts, min_occurrences=args.learn_min_count)
        path = learner.write(
            all_alerts,
            args.learning_mode,
            min_occurrences=args.learn_min_count,
        )
        print(
            f"  [LEARN] Wrote {learner.count_entries(learned)} process "
            f"whitelist entry group(s): {path}\n"
        )
        return

    # ---- Auto-load feeds silently (if cached) ----
    if threat_intel.needs_update():
        print("  [i] Downloading threat intel feeds (first run)...\n")
        threat_intel.update_feeds(quiet=True)
        n_ips = len(threat_intel.c2_ips)
        n_dom = len(threat_intel.malicious_domains)
        print(f"  [+] Loaded {n_ips:,} C2 IPs, {n_dom:,} domains from feeds.\n")

    # ---- PDF report helper ----
    def _maybe_pdf(
        alerts=None, profiles=None, investigations=None,
        dll_results=None, duration=None, connections=0,
        network_stats=None,
        task_findings=None,
        response_results=None,
        network_map_path=None,
    ):
        pdf_path = cfg.reporting.pdf_output or args.pdf
        if not pdf_path:
            return
        from .pdf_report import PDFReportGenerator
        gen = PDFReportGenerator()
        path = gen.generate(
            pdf_path,
            alerts=alerts or [],
            profiles=profiles or [],
            investigations=investigations,
            dll_results=dll_results,
            feed_status=threat_intel.get_feed_status(),
            scan_duration=duration,
            connection_count=connections,
            network_stats=network_stats,
            task_findings=task_findings,
            response_results=response_results,
            network_map_path=network_map_path,
        )
        print(f"\n  [PDF] Report saved: {path}\n")

    # ---- HTML report helper ----
    def _maybe_html(
        alerts=None, profiles=None, investigations=None,
        dll_results=None, duration=None, connections=0,
        network_stats=None,
        task_findings=None,
        response_results=None,
        network_map_path=None,
    ):
        html_path = cfg.reporting.html_output or args.html
        if not html_path:
            return
        gen = HTMLReportGenerator()
        path = gen.generate(
            html_path,
            alerts=alerts or [],
            profiles=profiles or [],
            investigations=investigations,
            dll_results=dll_results,
            feed_status=threat_intel.get_feed_status(),
            scan_duration=duration,
            connection_count=connections,
            network_stats=network_stats,
            task_findings=task_findings,
            response_results=response_results,
            network_map_path=network_map_path,
        )
        print(f"\n  [HTML] Report saved: {path}\n")

    # ---- DLL scan mode ----
    if args.dll_scan or args.dll_scan_pid is not None:
        dll_inspector = DLLInspector(threat_intel=threat_intel)
        reporter = Reporter(log_file=args.log)
        if args.dll_scan_pid is not None:
            print(f"  Scanning PID {args.dll_scan_pid} for injected DLLs...\n")
            result = dll_inspector.scan_process(args.dll_scan_pid)
            if result:
                reporter.print_dll_scan([result])
                _maybe_pdf(dll_results=[result] if result.is_suspicious else None)
                _maybe_html(dll_results=[result] if result.is_suspicious else None)
            else:
                print(f"  Could not scan PID {args.dll_scan_pid} (not found or access denied).\n")
        else:
            print("  Scanning all processes for injected DLLs...\n")
            results = dll_inspector.scan_all()
            reporter.print_dll_scan(results)
            _maybe_pdf(dll_results=results or None)
            _maybe_html(dll_results=results or None)
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
    monitor = TrafficMonitor(poll_interval=cfg.monitor.poll_interval)
    detector = AnomalyDetector(
        threat_intel=threat_intel,
        whitelist=whitelist,
        connection_rate_threshold=cfg.detector.connection_rate_threshold,
        rate_window_seconds=cfg.detector.rate_window_seconds,
        min_unique_ips_for_scan_alert=cfg.detector.min_unique_ips_for_scan_alert,
        port_scan_unique_ports=cfg.detector.port_scan_unique_ports,
    )
    reporter = Reporter(log_file=args.log)
    investigator = ProcessInvestigator()
    responder = ProcessResponder(quarantine_dir=args.quarantine_critical or None)
    map_generator = NetworkMapGenerator()
    session_alerts = []
    last_records = []
    response_results = []
    task_findings = []

    def _maybe_respond_to_critical(alerts):
        results = []
        if args.kill_critical:
            results.extend(responder.terminate_critical(alerts))
        if args.quarantine_critical is not None:
            results.extend(
                responder.quarantine_critical(alerts, detector.profiles)
            )
        if results:
            reporter.print_response_results(results)
        return results

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
        print("  Taking snapshot...\n")
        records = monitor.snapshot()

        # Enrich records with GeoIP data
        for rec in records:
            geoip.enrich_record(rec)

        alerts = detector.analyse(records)
        session_alerts.extend(alerts)
        total_alerts += len(alerts)
        reporter.report_alerts(alerts)
        notifier.send(alerts)
        response_results.extend(_maybe_respond_to_critical(alerts))
        risky = detector.get_risky_profiles(cfg.detector.min_risk_score)
        reporter.print_summary(risky)

        # --top: show top-N talkers
        if args.top:
            print(f"\n  Top {args.top} processes by connection count:\n")
            sorted_profiles = sorted(
                detector.profiles.values(),
                key=lambda p: p.total_connections,
                reverse=True,
            )[:args.top]
            for i, p in enumerate(sorted_profiles, 1):
                risk_tag = f" [risk: {p.risk_score}]" if p.risk_score else ""
                print(f"    {i:>2}. {p.name:<30} PID {p.pid:<8} {p.total_connections:>4} conn{risk_tag}")
            print()

        # --stats: network statistics summary
        if args.stats or args.top:
            stats = compute_stats(records, list(detector.profiles.values()), top_n=args.top or 10)
            if args.stats:
                print_stats(stats)

        investigations = []
        for profile in risky[:5]:
            inv = investigator.investigate(profile.pid)
            if inv:
                reporter.print_investigation(inv)
                investigations.append(inv)

        # Run a DLL scan on risky processes for the report
        dll_inspector = DLLInspector(threat_intel=threat_intel)
        dll_results_list = []
        scan_pids = {p.pid for p in risky[:10]}
        if scan_pids:
            print("  Scanning flagged processes for DLL injection...\n")
            for pid in scan_pids:
                result = dll_inspector.scan_process(pid)
                if result:
                    dll_results_list.append(result)
            suspicious = [r for r in dll_results_list if r.is_suspicious]
            if suspicious:
                reporter.print_dll_scan(suspicious)

        elapsed = time.time() - start_time

        # --export-csv: export alerts
        if args.export_csv:
            csv_path = export_alerts_csv(alerts, args.export_csv)
            print(f"  [CSV] Alerts exported: {csv_path}\n")
        if args.export_connections_csv:
            csv_path = export_connections_csv(records, args.export_connections_csv)
            print(f"  [CSV] Connections exported: {csv_path}\n")

        saved_map = None
        map_path = args.network_map or args.live_map
        if map_path:
            saved_map = map_generator.generate(
                map_path,
                records,
                alerts=alerts,
                refresh_seconds=args.map_refresh if args.live_map else None,
            )
            print(f"  [MAP] Network map saved: {saved_map}\n")

        if args.task_scan:
            print("  Scanning scheduled tasks for persistence indicators...\n")
            task_findings = TaskSchedulerScanner().scan()
            reporter.print_task_scan(task_findings)

        # Compute stats for PDF (always computed, cheap)
        from .stats import stats_to_dict
        snap_stats = compute_stats(records, list(detector.profiles.values()))
        snap_stats_dict = stats_to_dict(snap_stats)

        _maybe_pdf(
            alerts=alerts,
            profiles=list(detector.profiles.values()),
            investigations=investigations or None,
            dll_results=dll_results_list or None,
            duration=elapsed,
            connections=len(records),
            network_stats=snap_stats_dict,
            task_findings=task_findings,
            response_results=response_results,
            network_map_path=saved_map,
        )
        _maybe_html(
            alerts=alerts,
            profiles=list(detector.profiles.values()),
            investigations=investigations or None,
            dll_results=dll_results_list or None,
            duration=elapsed,
            connections=len(records),
            network_stats=snap_stats_dict,
            task_findings=task_findings,
            response_results=response_results,
            network_map_path=saved_map,
        )
        reporter.close()
        return

    # Continuous monitoring
    print(f"  Monitoring every {cfg.monitor.poll_interval}s — press Ctrl+C to stop.\n")

    try:
        for records in monitor.stream():
            if not running:
                break
            last_records = records

            # Enrich records with GeoIP data
            for rec in records:
                geoip.enrich_record(rec)

            alerts = detector.analyse(records)
            session_alerts.extend(alerts)
            total_alerts += len(alerts)

            if alerts:
                print()  # newline before alerts
                reporter.report_alerts(alerts)
                notifier.send(alerts)
                response_results.extend(_maybe_respond_to_critical(alerts))

            elapsed = time.time() - start_time
            reporter.print_status(
                len(records), len(detector.profiles), total_alerts, elapsed
            )

            if args.live_map:
                map_generator.generate(
                    args.live_map,
                    records,
                    alerts=session_alerts,
                    refresh_seconds=args.map_refresh,
                )

            if args.duration and elapsed >= args.duration:
                running = False
    except KeyboardInterrupt:
        pass

    # Final summary
    risky = detector.get_risky_profiles(cfg.detector.min_risk_score)
    reporter.print_summary(risky)

    investigations = []
    if risky:
        print(f"  {len(risky)} suspicious process(es) — running deep investigations...\n")
        for profile in risky[:10]:
            inv = investigator.investigate(profile.pid)
            if inv:
                reporter.print_investigation(inv)
                investigations.append(inv)

    elapsed = time.time() - start_time

    # --export-csv on continuous mode
    all_alerts = [a for p in detector.profiles.values() for a in p.alerts]
    if args.export_csv:
        csv_path = export_alerts_csv(all_alerts, args.export_csv)
        print(f"  [CSV] Alerts exported: {csv_path}\n")

    if args.network_map and last_records:
        saved_map = map_generator.generate(
            args.network_map,
            last_records,
            alerts=session_alerts or all_alerts,
        )
        print(f"  [MAP] Network map saved: {saved_map}\n")
    elif args.live_map and last_records:
        saved_map = args.live_map
    else:
        saved_map = None

    if args.task_scan:
        print("  Scanning scheduled tasks for persistence indicators...\n")
        task_findings = TaskSchedulerScanner().scan()
        reporter.print_task_scan(task_findings)

    _maybe_pdf(
        alerts=all_alerts,
        profiles=list(detector.profiles.values()),
        investigations=investigations or None,
        duration=elapsed,
        connections=total_alerts,  # approximate
        task_findings=task_findings,
        response_results=response_results,
        network_map_path=saved_map,
    )
    _maybe_html(
        alerts=all_alerts,
        profiles=list(detector.profiles.values()),
        investigations=investigations or None,
        duration=elapsed,
        connections=total_alerts,  # approximate
        task_findings=task_findings,
        response_results=response_results,
        network_map_path=saved_map,
    )
    reporter.close()
    print(f"  Done. {total_alerts} alert(s) raised during session.\n")


if __name__ == "__main__":
    main()
