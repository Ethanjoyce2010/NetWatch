"""
PDF Report Generator - produces professional security assessment reports.

Generates a multi-page PDF containing:
  - Executive summary with overall risk rating
  - Alert table grouped by severity
  - Process risk-score leaderboard
  - Deep investigation findings
  - DLL injection scan results
  - Threat intelligence feed status
"""

from __future__ import annotations

import logging
import time
from datetime import datetime
from pathlib import Path
from typing import Optional

from fpdf import FPDF

from .models import Alert, ProcessProfile, Severity

logger = logging.getLogger("netwatch.pdf_report")

# ======================================================================
# Colour palette (R, G, B)
# ======================================================================

_COLOURS = {
    Severity.LOW:      (52, 152, 219),   # blue
    Severity.MEDIUM:   (241, 196, 15),   # yellow
    Severity.HIGH:     (231, 76, 60),     # red
    Severity.CRITICAL: (155, 89, 182),    # purple
}

_DARK   = (30, 30, 30)
_WHITE  = (255, 255, 255)
_GREY   = (200, 200, 200)
_BG     = (245, 245, 245)
_ACCENT = (46, 204, 113)   # green accent


def _safe(text: str) -> str:
    """Replace Unicode characters unsupported by core PDF fonts (latin-1)."""
    _MAP = {
        "\u2014": "-",   # em dash
        "\u2013": "-",   # en dash
        "\u2018": "'",   # left single quote
        "\u2019": "'",   # right single quote
        "\u201c": '"',   # left double quote
        "\u201d": '"',   # right double quote
        "\u2026": "...", # ellipsis
        "\u2022": "*",   # bullet
        "\u00a0": " ",   # non-breaking space
        "\u200b": "",    # zero-width space
    }
    for char, repl in _MAP.items():
        text = text.replace(char, repl)
    # Fallback: drop anything still outside latin-1
    return text.encode("latin-1", errors="replace").decode("latin-1")


# ======================================================================
# Custom PDF class
# ======================================================================

class _NetWatchPDF(FPDF):
    """FPDF subclass with NetWatch header/footer branding."""

    def __init__(self, version: str = "2.2.0"):
        super().__init__(orientation="P", unit="mm", format="A4")
        self._version = version
        self.set_auto_page_break(auto=True, margin=20)

    def normalize_text(self, text):
        """Sanitize Unicode before core-font encoding."""
        return super().normalize_text(_safe(text))

    # -- Header --------------------------------------------------------

    def header(self):
        if self.page_no() == 1:
            return  # Cover page has its own header
        self.set_font("Helvetica", "B", 9)
        self.set_text_color(*_DARK)
        self.cell(0, 6, "NetWatch Security Report", ln=False)
        self.set_font("Helvetica", "", 8)
        self.set_text_color(128, 128, 128)
        self.cell(0, 6, f"v{self._version}", ln=True, align="R")
        self.set_draw_color(*_ACCENT)
        self.set_line_width(0.4)
        self.line(10, self.get_y(), 200, self.get_y())
        self.ln(4)

    # -- Footer --------------------------------------------------------

    def footer(self):
        self.set_y(-15)
        self.set_font("Helvetica", "I", 8)
        self.set_text_color(128, 128, 128)
        self.cell(0, 10, f"Page {self.page_no()}/{{nb}}", align="C")


# ======================================================================
# Public API
# ======================================================================

class PDFReportGenerator:
    """Generates a comprehensive NetWatch PDF report."""

    def __init__(self):
        from . import __version__
        self._version = __version__

    def generate(
        self,
        output_path: str,
        *,
        alerts: Optional[list[Alert]] = None,
        profiles: Optional[list[ProcessProfile]] = None,
        investigations: Optional[list] = None,
        dll_results: Optional[list] = None,
        feed_status: Optional[dict] = None,
        scan_duration: Optional[float] = None,
        connection_count: int = 0,
    ) -> str:
        """Build and save a PDF report. Returns the output file path."""
        alerts = alerts or []
        profiles = profiles or []

        pdf = _NetWatchPDF(self._version)
        pdf.alias_nb_pages()

        # ---- Cover page ----
        self._cover_page(pdf, alerts, profiles, scan_duration, connection_count)

        # ---- Executive summary ----
        pdf.add_page()
        self._executive_summary(pdf, alerts, profiles, scan_duration, connection_count)

        # ---- Alerts table ----
        if alerts:
            self._alerts_section(pdf, alerts)

        # ---- Risk-scored processes ----
        if profiles:
            self._process_section(pdf, profiles)

        # ---- Investigations ----
        if investigations:
            self._investigation_section(pdf, investigations)

        # ---- DLL scan results ----
        if dll_results:
            self._dll_section(pdf, dll_results)

        # ---- Threat intel feed status ----
        if feed_status:
            self._feed_section(pdf, feed_status)

        # ---- Recommended actions ----
        self._recommended_actions(pdf, alerts, profiles, dll_results)

        # ---- Save ----
        out = Path(output_path)
        out.parent.mkdir(parents=True, exist_ok=True)
        pdf.output(str(out))
        logger.info("PDF report saved: %s", out)
        return str(out.resolve())

    # ==================================================================
    # Cover page
    # ==================================================================

    def _cover_page(self, pdf: _NetWatchPDF, alerts, profiles, duration, connections):
        pdf.add_page()
        pdf.ln(50)

        # Title block
        pdf.set_font("Helvetica", "B", 32)
        pdf.set_text_color(*_DARK)
        pdf.cell(0, 14, "NetWatch", ln=True, align="C")

        pdf.set_font("Helvetica", "", 14)
        pdf.set_text_color(100, 100, 100)
        pdf.cell(0, 8, "Network Security Assessment Report", ln=True, align="C")
        pdf.ln(6)

        # Accent line
        pdf.set_draw_color(*_ACCENT)
        pdf.set_line_width(1)
        pdf.line(60, pdf.get_y(), 150, pdf.get_y())
        pdf.ln(12)

        # Metadata
        pdf.set_font("Helvetica", "", 11)
        pdf.set_text_color(*_DARK)
        now = datetime.now()
        meta_lines = [
            f"Generated:   {now.strftime('%Y-%m-%d  %H:%M:%S')}",
            f"Version:     {self._version}",
            f"Alerts:      {len(alerts)}",
            f"Processes:   {len(profiles)} profiled",
            f"Connections: {connections} observed",
        ]
        if duration:
            mins = int(duration // 60)
            secs = int(duration % 60)
            meta_lines.append(f"Duration:    {mins}m {secs}s")

        for line in meta_lines:
            pdf.cell(0, 7, line, ln=True, align="C")

        # Overall risk badge
        pdf.ln(14)
        risk = self._overall_risk(alerts)
        colour = _COLOURS.get(risk, _DARK)
        pdf.set_fill_color(*colour)
        pdf.set_text_color(*_WHITE)
        pdf.set_font("Helvetica", "B", 16)

        badge_text = f"  Overall Risk:  {risk.value}  "
        w = pdf.get_string_width(badge_text) + 20
        x = (210 - w) / 2
        pdf.set_x(x)
        pdf.cell(w, 12, badge_text, ln=True, fill=True, align="C")
        pdf.set_text_color(*_DARK)

    # ==================================================================
    # Executive summary
    # ==================================================================

    def _executive_summary(self, pdf: _NetWatchPDF, alerts, profiles, duration, connections):
        self._section_heading(pdf, "Executive Summary")

        sev_counts = {s: 0 for s in Severity}
        for a in alerts:
            sev_counts[a.severity] += 1

        # Severity breakdown mini-table
        pdf.set_font("Helvetica", "B", 10)
        headers = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
        col_w = 42
        start_x = (210 - col_w * 4) / 2
        pdf.set_x(start_x)
        for sev_name in headers:
            sev = Severity[sev_name]
            pdf.set_fill_color(*_COLOURS[sev])
            pdf.set_text_color(*_WHITE)
            pdf.cell(col_w, 8, sev_name, border=0, fill=True, align="C")
        pdf.ln()
        pdf.set_x(start_x)
        pdf.set_font("Helvetica", "", 12)
        for sev_name in headers:
            sev = Severity[sev_name]
            pdf.set_fill_color(240, 240, 240)
            pdf.set_text_color(*_DARK)
            pdf.cell(col_w, 8, str(sev_counts[sev]), border=1, fill=True, align="C")
        pdf.ln(10)

        # Prose summary
        pdf.set_font("Helvetica", "", 10)
        pdf.set_text_color(*_DARK)

        total = len(alerts)
        risky = [p for p in profiles if p.risk_score >= 30]
        summary_parts: list[str] = []
        summary_parts.append(
            f"NetWatch recorded {connections} network connections"
            + (f" over {int((duration or 0) // 60)}m {int((duration or 0) % 60)}s" if duration else "")
            + f", profiling {len(profiles)} unique processes."
        )
        if total:
            summary_parts.append(
                f"A total of {total} alert(s) were raised: "
                f"{sev_counts[Severity.CRITICAL]} critical, "
                f"{sev_counts[Severity.HIGH]} high, "
                f"{sev_counts[Severity.MEDIUM]} medium, "
                f"{sev_counts[Severity.LOW]} low."
            )
        else:
            summary_parts.append("No alerts were raised during the scan.")

        if risky:
            summary_parts.append(
                f"{len(risky)} process(es) scored 30 or above on the risk scale "
                "and warrant further review."
            )

        pdf.multi_cell(0, 5, "  ".join(summary_parts))

    # ==================================================================
    # Alerts table
    # ==================================================================

    def _alerts_section(self, pdf: _NetWatchPDF, alerts: list[Alert]):
        self._section_heading(pdf, "Alert Details")

        # Sort: CRITICAL first
        order = {Severity.CRITICAL: 0, Severity.HIGH: 1, Severity.MEDIUM: 2, Severity.LOW: 3}
        alerts_sorted = sorted(alerts, key=lambda a: order.get(a.severity, 4))

        col_widths = [22, 30, 50, 88]  # severity, PID/name, rule, description
        self._table_header(pdf, ["Severity", "Process", "Rule", "Description"], col_widths)

        pdf.set_font("Helvetica", "", 8)
        for alert in alerts_sorted:
            colour = _COLOURS.get(alert.severity, _DARK)
            h = self._row_height(pdf, alert.description, col_widths[3])

            # Page break check
            if pdf.get_y() + h > 275:
                pdf.add_page()
                self._table_header(pdf, ["Severity", "Process", "Rule", "Description"], col_widths)
                pdf.set_font("Helvetica", "", 8)

            y_start = pdf.get_y()
            x_start = pdf.get_x()

            # Severity cell with colour
            pdf.set_fill_color(*colour)
            pdf.set_text_color(*_WHITE)
            pdf.set_font("Helvetica", "B", 8)
            pdf.cell(col_widths[0], h, f" {alert.severity.value}", border=1, fill=True)

            pdf.set_text_color(*_DARK)
            pdf.set_font("Helvetica", "", 8)
            process_text = f"{alert.pid} {alert.process_name}"
            if len(process_text) > 16:
                process_text = process_text[:16]
            pdf.cell(col_widths[1], h, f" {process_text}", border=1)
            pdf.cell(col_widths[2], h, f" {alert.rule_name}", border=1)

            # Description (may wrap)
            x_desc = pdf.get_x()
            pdf.multi_cell(col_widths[3], 4.5, f" {alert.description}", border=1)
            # Align heights if multi_cell expanded
            y_end = pdf.get_y()
            actual_h = y_end - y_start
            if actual_h > h:
                # Redraw borders to match
                pass  # fpdf2 handles this well enough

    # ==================================================================
    # Process risk table
    # ==================================================================

    def _process_section(self, pdf: _NetWatchPDF, profiles: list[ProcessProfile]):
        self._section_heading(pdf, "Process Risk Scores")

        # Only show processes with at least 1 alert
        risky = sorted(
            [p for p in profiles if p.alerts],
            key=lambda p: p.risk_score, reverse=True,
        )
        if not risky:
            pdf.set_font("Helvetica", "I", 10)
            pdf.cell(0, 6, "No processes reached the alert threshold.", ln=True)
            return

        col_widths = [18, 44, 18, 18, 24, 24, 44]
        headers = ["PID", "Name", "Risk", "Alerts", "Unique IPs", "Ports", "User"]
        self._table_header(pdf, headers, col_widths)

        pdf.set_font("Helvetica", "", 8)
        for p in risky[:40]:  # Cap at 40 rows
            if pdf.get_y() > 270:
                pdf.add_page()
                self._table_header(pdf, headers, col_widths)
                pdf.set_font("Helvetica", "", 8)

            risk = p.risk_score
            if risk >= 50:
                pdf.set_fill_color(*_COLOURS[Severity.CRITICAL])
            elif risk >= 30:
                pdf.set_fill_color(*_COLOURS[Severity.HIGH])
            elif risk >= 15:
                pdf.set_fill_color(*_COLOURS[Severity.MEDIUM])
            else:
                pdf.set_fill_color(*_COLOURS[Severity.LOW])

            pdf.set_text_color(*_WHITE)
            pdf.set_font("Helvetica", "B", 8)
            pdf.cell(col_widths[0], 6, f" {p.pid}", border=1, fill=True)

            pdf.set_text_color(*_DARK)
            pdf.set_font("Helvetica", "", 8)
            name = p.name[:24] if len(p.name) > 24 else p.name
            pdf.cell(col_widths[1], 6, f" {name}", border=1)

            # Risk score cell coloured
            pdf.set_fill_color(*(
                _COLOURS[Severity.CRITICAL] if risk >= 50 else
                _COLOURS[Severity.HIGH] if risk >= 30 else
                _COLOURS[Severity.MEDIUM] if risk >= 15 else
                _COLOURS[Severity.LOW]
            ))
            pdf.set_text_color(*_WHITE)
            pdf.set_font("Helvetica", "B", 8)
            pdf.cell(col_widths[2], 6, f" {risk}", border=1, fill=True, align="C")

            pdf.set_text_color(*_DARK)
            pdf.set_font("Helvetica", "", 8)
            pdf.cell(col_widths[3], 6, f" {len(p.alerts)}", border=1, align="C")
            pdf.cell(col_widths[4], 6, f" {len(p.unique_remote_ips)}", border=1, align="C")
            pdf.cell(col_widths[5], 6, f" {len(p.unique_remote_ports)}", border=1, align="C")
            pdf.cell(col_widths[6], 6, f" {(p.username or 'N/A')[:24]}", border=1)
            pdf.ln()

    # ==================================================================
    # Investigation details
    # ==================================================================

    def _investigation_section(self, pdf: _NetWatchPDF, investigations: list):
        self._section_heading(pdf, "Process Investigations")

        for inv in investigations:
            if pdf.get_y() > 240:
                pdf.add_page()

            pdf.set_font("Helvetica", "B", 10)
            pdf.set_fill_color(*_ACCENT)
            pdf.set_text_color(*_WHITE)
            pdf.cell(0, 7, f"  PID {inv.pid} - {inv.name}", ln=True, fill=True)
            pdf.set_text_color(*_DARK)
            pdf.ln(1)

            fields = [
                ("Executable", inv.exe_path),
                ("Exists on disk", "Yes" if inv.exe_exists_on_disk else "No" if inv.exe_exists_on_disk is not None else "Unknown"),
                ("Command line", (inv.cmdline or "")[:100]),
                ("User", inv.username),
                ("Status", inv.status),
                ("Parent", f"PID {inv.parent_pid} ({inv.parent_name})" if inv.parent_pid else None),
                ("Threads", inv.num_threads),
                ("Memory", f"{inv.memory_mb:.1f} MB" if inv.memory_mb else None),
                ("CPU", f"{inv.cpu_percent:.1f}%" if inv.cpu_percent is not None else None),
            ]

            pdf.set_font("Helvetica", "", 9)
            for label, value in fields:
                if value is not None:
                    pdf.set_font("Helvetica", "B", 9)
                    pdf.cell(35, 5, f"  {label}:", border=0)
                    pdf.set_font("Helvetica", "", 9)
                    pdf.cell(0, 5, str(value), ln=True)

            # Connections
            if inv.connections:
                pdf.set_font("Helvetica", "B", 9)
                pdf.cell(0, 5, f"  Active connections ({len(inv.connections)}):", ln=True)
                pdf.set_font("Helvetica", "", 8)
                for c in inv.connections[:8]:
                    pdf.cell(0, 4, f"    {c['local']}  ->  {c['remote']}  [{c['status']}]", ln=True)
                if len(inv.connections) > 8:
                    pdf.cell(0, 4, f"    ... and {len(inv.connections) - 8} more", ln=True)

            # Suspicious DLLs
            if inv.suspicious_dlls:
                pdf.set_font("Helvetica", "B", 9)
                pdf.set_text_color(*_COLOURS[Severity.HIGH])
                pdf.cell(0, 5, f"  Suspicious DLLs ({len(inv.suspicious_dlls)}):", ln=True)
                pdf.set_text_color(*_DARK)
                pdf.set_font("Helvetica", "", 8)
                for dll in inv.suspicious_dlls[:10]:
                    pdf.cell(0, 4, f"    {dll['name']} - {dll['path']}", ln=True)
                    for reason in dll.get("reasons", []):
                        pdf.set_text_color(*_COLOURS[Severity.MEDIUM])
                        pdf.cell(0, 4, f"      -> {reason}", ln=True)
                        pdf.set_text_color(*_DARK)

            if inv.exe_exists_on_disk is False:
                pdf.set_font("Helvetica", "B", 9)
                pdf.set_text_color(*_COLOURS[Severity.CRITICAL])
                pdf.cell(0, 5, "  WARNING: Executable not found on disk - possible fileless malware", ln=True)
                pdf.set_text_color(*_DARK)

            pdf.ln(4)

    # ==================================================================
    # DLL scan results
    # ==================================================================

    def _dll_section(self, pdf: _NetWatchPDF, dll_results: list):
        self._section_heading(pdf, "DLL Injection Scan")

        total_findings = sum(len(r.suspicious_modules) for r in dll_results)
        pdf.set_font("Helvetica", "", 10)
        pdf.cell(
            0, 6,
            f"Scanned processes with findings: {len(dll_results)}  |  "
            f"Total suspicious modules: {total_findings}",
            ln=True,
        )
        pdf.ln(2)

        for r in dll_results:
            if pdf.get_y() > 250:
                pdf.add_page()

            n_sus = len(r.suspicious_modules)
            colour = _COLOURS[Severity.CRITICAL] if n_sus >= 3 else _COLOURS[Severity.HIGH]
            pdf.set_font("Helvetica", "B", 9)
            pdf.set_fill_color(*colour)
            pdf.set_text_color(*_WHITE)
            pdf.cell(
                0, 6,
                f"  PID {r.pid} - {r.process_name}  "
                f"({r.total_modules} loaded, {n_sus} suspicious)",
                ln=True, fill=True,
            )
            pdf.set_text_color(*_DARK)

            pdf.set_font("Helvetica", "", 8)
            for dll in r.suspicious_modules:
                disk_tag = " [MISSING]" if not dll.get("exists_on_disk", True) else ""
                pdf.cell(0, 4, f"    {dll['name']}{disk_tag} - {dll['path']}", ln=True)
                for reason in dll.get("reasons", []):
                    pdf.set_text_color(*_COLOURS[Severity.MEDIUM])
                    pdf.cell(0, 4, f"      -> {reason}", ln=True)
                    pdf.set_text_color(*_DARK)
            pdf.ln(2)

    # ==================================================================
    # Feed status
    # ==================================================================

    def _feed_section(self, pdf: _NetWatchPDF, feed_status: dict):
        self._section_heading(pdf, "Threat Intelligence Feeds")

        col_widths = [40, 75, 40, 35]
        self._table_header(pdf, ["Feed", "Description", "Last Updated", "Entries"], col_widths)

        pdf.set_font("Helvetica", "", 8)
        for name, status in feed_status.items():
            if pdf.get_y() > 270:
                pdf.add_page()
            updated = status.last_updated.strftime("%Y-%m-%d %H:%M") if status.last_updated else "never"
            pdf.cell(col_widths[0], 6, f" {name}", border=1)
            desc = status.description[:40] if len(status.description) > 40 else status.description
            pdf.cell(col_widths[1], 6, f" {desc}", border=1)
            pdf.cell(col_widths[2], 6, f" {updated}", border=1, align="C")
            pdf.cell(col_widths[3], 6, f" {status.entry_count}", border=1, align="C")
            pdf.ln()

    # ==================================================================
    # Recommended actions
    # ==================================================================

    def _recommended_actions(
        self,
        pdf: _NetWatchPDF,
        alerts: list[Alert],
        profiles: list[ProcessProfile],
        dll_results: Optional[list],
    ):
        """Generate prioritised remediation recommendations based on findings."""
        actions: list[tuple[str, str, str]] = []  # (priority, action, rationale)

        sev_counts = {s: 0 for s in Severity}
        for a in alerts:
            sev_counts[a.severity] += 1

        # -- Critical / High alert actions --
        if sev_counts[Severity.CRITICAL]:
            actions.append((
                "CRITICAL",
                "Isolate affected hosts and investigate critical alerts immediately",
                f"{sev_counts[Severity.CRITICAL]} critical alert(s) detected - "
                "these may indicate active compromise or C2 communication.",
            ))
        if sev_counts[Severity.HIGH]:
            actions.append((
                "HIGH",
                "Review and triage high-severity alerts within 24 hours",
                f"{sev_counts[Severity.HIGH]} high-severity alert(s) require "
                "prompt analysis to rule out malicious activity.",
            ))

        # -- C2 / threat-intel hits --
        c2_alerts = [a for a in alerts if "c2" in a.rule_name.lower() or "threat" in a.rule_name.lower()]
        if c2_alerts:
            actions.append((
                "CRITICAL",
                "Block identified C2 IP addresses at the firewall",
                f"{len(c2_alerts)} connection(s) matched known command-and-control "
                "indicators. Add them to your perimeter blocklist.",
            ))

        # -- Risky processes --
        risky = [p for p in profiles if p.risk_score >= 30]
        if risky:
            names = ", ".join(dict.fromkeys(p.name for p in risky[:5]))
            actions.append((
                "HIGH",
                f"Investigate high-risk processes: {names}",
                f"{len(risky)} process(es) scored >= 30 on the risk scale. "
                "Verify they are authorised and review their network behaviour.",
            ))

        # -- External listeners --
        ext_alerts = [a for a in alerts if "external listener" in a.rule_name.lower()]
        if len(ext_alerts) > 10:
            actions.append((
                "MEDIUM",
                "Audit services listening on all interfaces (0.0.0.0)",
                f"{len(ext_alerts)} processes are accepting connections on all "
                "interfaces. Restrict bindings to localhost or specific IPs where possible.",
            ))

        # -- DLL findings --
        if dll_results:
            suspicious_count = sum(
                len(entry.suspicious_modules) for entry in dll_results
            )
            if suspicious_count:
                actions.append((
                    "HIGH",
                    "Investigate suspicious DLL modules flagged by the inspector",
                    f"{suspicious_count} DLL(s) matched injection or side-loading "
                    "indicators. Validate their origin and digital signatures.",
                ))

        # -- Non-standard DNS --
        dns_alerts = [a for a in alerts if "dns" in a.rule_name.lower()]
        if dns_alerts:
            actions.append((
                "MEDIUM",
                "Review processes using non-standard DNS ports",
                f"{len(dns_alerts)} process(es) are performing DNS on unusual ports, "
                "which can indicate DNS tunnelling or data exfiltration.",
            ))

        # -- General hardening (always include) --
        actions.append((
            "LOW",
            "Schedule regular NetWatch scans to establish a network baseline",
            "Periodic monitoring helps distinguish normal traffic from anomalies "
            "and improves detection accuracy over time.",
        ))
        if sev_counts[Severity.MEDIUM] > 20:
            actions.append((
                "LOW",
                "Consider tuning detection thresholds to reduce alert noise",
                f"{sev_counts[Severity.MEDIUM]} medium alerts may include benign "
                "activity. Whitelist known services to improve signal-to-noise.",
            ))

        # -- Render --
        self._section_heading(pdf, "Recommended Actions")

        pdf.set_font("Helvetica", "", 9)
        pdf.set_text_color(*_DARK)
        pdf.multi_cell(
            0, 5,
            "The following actions are recommended based on the findings in this report, "
            "listed in order of priority.",
        )
        pdf.ln(3)

        priority_colour = {
            "CRITICAL": _COLOURS[Severity.CRITICAL],
            "HIGH":     _COLOURS[Severity.HIGH],
            "MEDIUM":   _COLOURS[Severity.MEDIUM],
            "LOW":      _COLOURS[Severity.LOW],
        }

        for i, (priority, action, rationale) in enumerate(actions, 1):
            if pdf.get_y() > 255:
                pdf.add_page()

            colour = priority_colour.get(priority, _DARK)

            # Priority badge
            pdf.set_font("Helvetica", "B", 8)
            pdf.set_fill_color(*colour)
            pdf.set_text_color(*_WHITE)
            badge = f" {priority} "
            badge_w = max(20, pdf.get_string_width(badge) + 6)
            pdf.cell(badge_w, 6, badge, fill=True)

            # Action title
            pdf.set_font("Helvetica", "B", 9)
            pdf.set_text_color(*_DARK)
            pdf.cell(0, 6, f"  {i}. {action}", ln=True)

            # Rationale
            pdf.set_font("Helvetica", "", 8)
            pdf.set_text_color(80, 80, 80)
            pdf.set_x(16)
            pdf.multi_cell(0, 4, rationale)
            pdf.ln(2)

    # ==================================================================
    # Helpers
    # ==================================================================

    @staticmethod
    def _section_heading(pdf: _NetWatchPDF, title: str):
        """Render a styled section heading with green accent bar."""
        if pdf.get_y() > 260:
            pdf.add_page()
        pdf.ln(4)
        pdf.set_draw_color(*_ACCENT)
        pdf.set_line_width(0.8)
        pdf.line(10, pdf.get_y(), 14, pdf.get_y())
        pdf.set_font("Helvetica", "B", 13)
        pdf.set_text_color(*_DARK)
        pdf.set_x(16)
        pdf.cell(0, 7, title, ln=True)
        pdf.ln(2)

    @staticmethod
    def _table_header(pdf: _NetWatchPDF, headers: list[str], widths: list[int]):
        """Render a dark header row for a table."""
        pdf.set_fill_color(50, 50, 50)
        pdf.set_text_color(*_WHITE)
        pdf.set_font("Helvetica", "B", 8)
        for hdr, w in zip(headers, widths):
            pdf.cell(w, 6, f" {hdr}", border=1, fill=True)
        pdf.ln()
        pdf.set_text_color(*_DARK)

    @staticmethod
    def _overall_risk(alerts: list[Alert]) -> Severity:
        """Determine the overall risk level from all alerts."""
        if not alerts:
            return Severity.LOW
        if any(a.severity == Severity.CRITICAL for a in alerts):
            return Severity.CRITICAL
        if any(a.severity == Severity.HIGH for a in alerts):
            return Severity.HIGH
        if any(a.severity == Severity.MEDIUM for a in alerts):
            return Severity.MEDIUM
        return Severity.LOW

    @staticmethod
    def _row_height(pdf: _NetWatchPDF, text: str, col_width: float) -> float:
        """Estimate how tall a multi_cell row will be."""
        char_width = pdf.get_string_width("x")
        if char_width == 0:
            return 5
        chars_per_line = max(1, int(col_width / char_width))
        lines = max(1, -(-len(text) // chars_per_line))  # ceil division
        return max(6, lines * 4.5)
