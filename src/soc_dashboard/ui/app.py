from __future__ import annotations

from collections import deque
from datetime import datetime
import ipaddress
import random
import socket
import time

import psutil
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.widgets import Footer, Header, Input, Log, Static, TabbedContent, TabPane

from soc_dashboard.config import DashboardConfig
from soc_dashboard.engine.alert_manager import AlertManager
from soc_dashboard.engine.analytics import alerts_by_severity, targeted_destinations, top_attacking_ips
from soc_dashboard.engine.detection_engine import DetectionEngine
from soc_dashboard.engine.event_engine import EventEngine
from soc_dashboard.engine.log_parser import LogParser
from soc_dashboard.engine.network_monitor import NetworkMonitor
from soc_dashboard.engine.process_monitor import ProcessMonitor
from soc_dashboard.engine.threat_intel import MITRE_TECHNIQUES, ThreatIntelModule
from soc_dashboard.exporter import Exporter
from soc_dashboard.models import IncidentEntry, SecurityEvent, Severity, SystemHealth


def _severity_style(severity: Severity) -> str:
    return {
        Severity.CRITICAL: "bold red",
        Severity.HIGH: "bold yellow",
        Severity.MEDIUM: "yellow",
        Severity.LOW: "green",
        Severity.INFO: "cyan",
    }.get(severity, "white")


def _bar(value: float, width: int = 18) -> str:
    filled = int((max(0, min(value, 100)) / 100.0) * width)
    return "█" * filled + "░" * (width - filled)


class SOCDashboardApp(App[None]):
    CSS = """
    Screen { background: #0a0f0a; color: #d8ffd8; }
    Header { color: cyan; }
    Footer { background: #071407; color: #8af58a; }
    #toolbar { height: 3; }
    #statusline { height: 3; }
    Input { border: tall #206b20; }
    Log { border: round #206b20; }
    Static.panel { border: round #206b20; }
    """
    TITLE = "Threat Intelligence & SOC Dashboard"
    SUB_TITLE = "ASCII Terminal SOC Console"

    BINDINGS = [
        Binding("q", "quit", "Quit"),
        Binding("p", "toggle_pause", "Pause"),
        Binding("r", "manual_refresh", "Refresh"),
        Binding("f", "focus_filter", "Filter"),
        Binding("e", "export_snapshot", "Export"),
        Binding("x", "cycle_export_format", "Export Format"),
        Binding("s", "cycle_sort", "Sort"),
        Binding("t", "toggle_theme", "Theme"),
        Binding("n", "scan_local_network", "Scan LAN"),
        Binding("1", "go_tab('overview')", "Overview"),
        Binding("2", "go_tab('alerts')", "Alerts"),
        Binding("3", "go_tab('intel')", "Intel"),
        Binding("4", "go_tab('network')", "Network"),
        Binding("5", "go_tab('threatmap')", "Threat Map"),
        Binding("6", "go_tab('lookup')", "IOC Lookup"),
        Binding("7", "go_tab('mitre')", "MITRE"),
        Binding("8", "go_tab('logs')", "Logs"),
        Binding("9", "go_tab('process')", "Process"),
        Binding("0", "go_tab('lanscan')", "LAN Scan"),
    ]

    paused = False

    def __init__(self, config: DashboardConfig) -> None:
        super().__init__()
        self.config = config
        self.event_engine = EventEngine(max_events=config.max_events)
        self.detector = DetectionEngine()
        self.alerts = AlertManager()
        self.ti = ThreatIntelModule()
        self.network_monitor = NetworkMonitor()
        self.process_monitor = ProcessMonitor()
        self.log_parser = LogParser()
        self.exporter = Exporter(config.export_dir)
        self.timeline: deque[IncidentEntry] = deque(maxlen=config.max_timeline)
        self.filter_term = ""
        self.lookup_term = ""
        self.start_ts = time.time()
        self.export_format = "json"
        self.sort_mode = "time_desc"
        self.network_scan_text = "Press 'n' to scan local /24 network, or use target scan input."

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        with Horizontal(id="toolbar"):
            yield Input(placeholder="Filter alerts/logs...", id="filter")
            yield Input(placeholder="IOC lookup term (ip/domain/hash/url)...", id="lookup_input")
            yield Input(placeholder="Target scan (e.g. 192.168.1.10:22,80,443)", id="target_scan_input")
        with TabbedContent(initial="overview"):
            with TabPane("SOC Overview", id="overview"):
                yield Static(classes="panel", id="overview_panel")
            with TabPane("Security Alerts", id="alerts"):
                yield Static(classes="panel", id="alerts_panel")
            with TabPane("Threat Intel", id="intel"):
                yield Static(classes="panel", id="intel_panel")
            with TabPane("Network", id="network"):
                yield Static(classes="panel", id="network_panel")
            with TabPane("Threat Map", id="threatmap"):
                yield Static(classes="panel", id="threatmap_panel")
            with TabPane("IOC Lookup", id="lookup"):
                yield Static(classes="panel", id="lookup_panel")
            with TabPane("MITRE ATT&CK", id="mitre"):
                yield Static(classes="panel", id="mitre_panel")
            with TabPane("Log Viewer", id="logs"):
                yield Log(id="log_view")
            with TabPane("Process Monitor", id="process"):
                yield Static(classes="panel", id="process_panel")
            with TabPane("LAN Scan", id="lanscan"):
                yield Static(classes="panel", id="lanscan_panel")
            with TabPane("Timeline & Analytics", id="timeline"):
                yield Static(classes="panel", id="timeline_panel")
        with Vertical(id="statusline"):
            yield Static(id="status")
        yield Footer()

    def on_mount(self) -> None:
        self.set_interval(self.config.refresh_interval, self.refresh_dashboard)
        self.refresh_dashboard()

    def action_go_tab(self, tab_id: str) -> None:
        tabs = self.query_one(TabbedContent)
        tabs.active = tab_id

    def action_toggle_pause(self) -> None:
        self.paused = not self.paused
        self._status(f"Auto-refresh {'paused' if self.paused else 'resumed'}")

    def action_manual_refresh(self) -> None:
        self.refresh_dashboard()

    def action_focus_filter(self) -> None:
        self.query_one("#filter", Input).focus()

    def action_export_snapshot(self) -> None:
        events = self._filtered_events(self.event_engine.all_events())
        path = self.exporter.export_all(events, self.ti.get_recent_iocs(), fmt=self.export_format)
        self._status(f"Exported snapshot to {path}")

    def action_cycle_export_format(self) -> None:
        formats = ["json", "csv", "txt", "html", "md"]
        idx = (formats.index(self.export_format) + 1) % len(formats)
        self.export_format = formats[idx]
        self._status(f"Export format set to {self.export_format.upper()}")

    def action_cycle_sort(self) -> None:
        modes = ["time_desc", "severity_desc", "source_asc"]
        idx = (modes.index(self.sort_mode) + 1) % len(modes)
        self.sort_mode = modes[idx]
        self._render_alerts()
        self._status(f"Alert sort: {self.sort_mode}")

    def action_toggle_theme(self) -> None:
        self.dark = not self.dark
        self._status(f"Theme switched to {'dark' if self.dark else 'light'}")

    def action_scan_local_network(self) -> None:
        self._status("Running local subnet discovery scan...")
        self.run_worker(self._scan_local_network_worker, thread=True)

    def on_input_changed(self, event: Input.Changed) -> None:
        if event.input.id == "filter":
            self.filter_term = event.value.strip()
        elif event.input.id == "lookup_input":
            self.lookup_term = event.value.strip()
        self.refresh_dashboard()

    def on_input_submitted(self, event: Input.Submitted) -> None:
        if event.input.id == "target_scan_input" and event.value.strip():
            spec = event.value.strip()
            self._status(f"Running target scan: {spec}")
            self.run_worker(lambda: self._scan_target_worker(spec), thread=True)

    def refresh_dashboard(self) -> None:
        if self.paused:
            return
        new_events = self.event_engine.generate(burst=3)
        new_events = self.detector.enrich(new_events)
        self.ti.refresh_feeds()
        self.log_parser.ingest_simulated()
        for event in new_events:
            self.timeline.append(IncidentEntry(event.timestamp, f"{event.event_type}: {event.description}"))
        self._render_overview()
        self._render_alerts()
        self._render_intel()
        self._render_network()
        self._render_threat_map()
        self._render_lookup()
        self._render_mitre()
        self._render_logs()
        self._render_processes()
        self._render_lan_scan()
        self._render_timeline_analytics()
        self._status("Live feed updated")

    def _system_health(self) -> SystemHealth:
        net = psutil.net_io_counters()
        uptime_s = max(1, int(time.time() - psutil.boot_time()))
        uptime_h = uptime_s // 3600
        uptime_m = (uptime_s % 3600) // 60
        return SystemHealth(
            cpu_percent=psutil.cpu_percent(interval=0),
            memory_percent=psutil.virtual_memory().percent,
            disk_percent=psutil.disk_usage("/").percent,
            network_mbps=((net.bytes_recv + net.bytes_sent) / max(1, int(time.time() - self.start_ts))) / (1024 * 1024),
            active_users=len(psutil.users()),
            sessions=random.randint(1, 12),
            running_services=len(psutil.pids()),
            uptime=f"{uptime_h}h {uptime_m}m",
        )

    def _render_overview(self) -> None:
        health = self._system_health()
        net = self.network_monitor.snapshot()
        sev = self.alerts.summarize(self._filtered_events(self.event_engine.all_events()))
        grid = Table.grid(expand=True)
        grid.add_column()
        grid.add_column()
        grid.add_column()
        left = (
            f"CPU   {_bar(health.cpu_percent)} {health.cpu_percent:5.1f}%\n"
            f"RAM   {_bar(health.memory_percent)} {health.memory_percent:5.1f}%\n"
            f"Disk  {_bar(health.disk_percent)} {health.disk_percent:5.1f}%\n"
            f"Uptime: {health.uptime}"
        )
        mid = (
            f"Connections   {net['active_connections']}\n"
            f"Bandwidth     {health.network_mbps:6.2f} MiB/s\n"
            f"Active Users  {health.active_users}\n"
            f"Sessions      {health.sessions}\n"
            f"Services      {health.running_services}"
        )
        right = (
            f"[red]CRITICAL[/] {sev['critical']:3d}\n"
            f"[yellow]HIGH[/]     {sev['high']:3d}\n"
            f"[bright_yellow]MEDIUM[/]   {sev['medium']:3d}\n"
            f"[green]LOW[/]      {sev['low']:3d}"
        )
        grid.add_row(Panel(left, title="SYSTEM HEALTH"), Panel(mid, title="NETWORK OVERVIEW"), Panel(right, title="ACTIVE ALERTS"))
        self.query_one("#overview_panel", Static).update(grid)

    def _filtered_events(self, events: list[SecurityEvent]) -> list[SecurityEvent]:
        if not self.filter_term:
            return events
        needle = self.filter_term.lower()
        return [
            event
            for event in events
            if needle in event.description.lower()
            or needle in event.source_ip.lower()
            or needle in event.event_type.lower()
            or needle in event.destination.lower()
        ]

    def _render_alerts(self) -> None:
        table = Table(expand=True, show_edge=True)
        table.add_column("Time", no_wrap=True)
        table.add_column("Severity")
        table.add_column("Source")
        table.add_column("Destination")
        table.add_column("Description")
        events = self._filtered_events(self.event_engine.all_events())
        if self.sort_mode == "severity_desc":
            order = {
                Severity.CRITICAL: 5,
                Severity.HIGH: 4,
                Severity.MEDIUM: 3,
                Severity.LOW: 2,
                Severity.INFO: 1,
            }
            events = sorted(events, key=lambda event: order[event.severity], reverse=True)
        elif self.sort_mode == "source_asc":
            events = sorted(events, key=lambda event: event.source_ip)
        else:
            events = sorted(events, key=lambda event: event.timestamp, reverse=True)

        for event in events[:20]:
            table.add_row(
                event.timestamp.strftime("%H:%M:%S"),
                f"[{_severity_style(event.severity)}]{event.severity.value.upper()}[/]",
                event.source_ip,
                event.destination,
                event.description,
            )
        self.query_one("#alerts_panel", Static).update(Panel(table, title="LIVE SECURITY ALERT FEED"))

    def _render_intel(self) -> None:
        table = Table(expand=True, show_edge=True)
        table.add_column("Type")
        table.add_column("IOC")
        table.add_column("Reputation")
        table.add_column("Country")
        table.add_column("ASN")
        table.add_column("Score")
        table.add_column("Last Seen")
        for ioc in self.ti.get_recent_iocs(limit=12):
            style = "red" if ioc.reputation == "malicious" else "yellow"
            table.add_row(
                ioc.ioc_type.upper(),
                ioc.value,
                f"[{style}]{ioc.reputation.upper()}[/]",
                ioc.country,
                ioc.asn,
                str(ioc.score),
                ioc.last_seen.strftime("%H:%M:%S"),
            )
        self.query_one("#intel_panel", Static).update(Panel(table, title="THREAT INTELLIGENCE FEEDS"))

    def _render_network(self) -> None:
        snapshot = self.network_monitor.snapshot()
        top = (
            f"Active Connections : {snapshot['active_connections']}\n"
            f"Open Ports         : {snapshot['open_ports']}\n"
            f"Listening Services : {snapshot['listening_services']}\n"
            f"DNS Requests       : {snapshot['dns_requests']}\n"
            f"HTTP Requests      : {snapshot['http_requests']}\n"
            f"SSH Sessions       : {snapshot['ssh_sessions']}\n"
            f"TLS Connections    : {snapshot['tls_connections']}\n"
            f"Internal Traffic   : {snapshot['internal_traffic']}\n"
            f"External Traffic   : {snapshot['external_traffic']}"
        )
        net_view = Table.grid(expand=True)
        net_view.add_column(ratio=1)
        net_view.add_column(ratio=1)
        net_view.add_row(
            Panel(top, title="NETWORK METRICS"),
            Panel(NetworkMonitor.ascii_topology(), title="ASCII TOPOLOGY"),
        )
        self.query_one("#network_panel", Static).update(net_view)

    def _render_lan_scan(self) -> None:
        scan_grid = Table.grid(expand=True)
        scan_grid.add_column(ratio=2)
        scan_grid.add_column(ratio=1)
        scan_grid.add_row(
            Panel(
                self.network_scan_text,
                title="REAL NETWORK/IP/PORT SCAN RESULTS",
            ),
            Panel(
                "n: scan local subnet\n"
                "Input: target_scan_input + Enter\n"
                "Format: 192.168.1.10:22,80,443\n"
                "Use only on authorized systems.",
                title="SCAN CONTROLS",
            ),
        )
        self.query_one("#lanscan_panel", Static).update(scan_grid)

    def _scan_local_network_worker(self) -> None:
        subnet = self.network_monitor.local_subnet_cidr()
        local_ip = self.network_monitor.local_ipv4()
        hosts = self.network_monitor.discover_subnet_hosts(subnet_cidr=subnet, max_hosts=64, timeout=0.12)
        lines = [f"Local IP: {local_ip}", f"Subnet: {subnet}", f"Discovered live hosts ({len(hosts)}):"]
        lines.extend(f" - {ip}" for ip in hosts[:30])
        if len(hosts) > 30:
            lines.append(f" ... and {len(hosts) - 30} more")
        text = "\n".join(lines)
        self.call_from_thread(self._update_scan_text, text)
        self.call_from_thread(self._status, f"LAN scan complete: {len(hosts)} host(s)")

    def _scan_target_worker(self, spec: str) -> None:
        try:
            target_ip, ports = self._parse_target_spec(spec)
            open_ports = self.network_monitor.scan_ports(target_ip, ports=ports, timeout=0.2)
            lines = [f"Target: {target_ip}", f"Requested ports: {','.join(str(p) for p in ports)}", "Open ports:"]
            if not open_ports:
                lines.append(" - none found")
            else:
                lines.extend(f" - {port}/tcp ({svc})" for port, svc in open_ports)
            text = "\n".join(lines)
            self.call_from_thread(self._update_scan_text, text)
            self.call_from_thread(self._status, f"Target scan complete: {target_ip}")
        except ValueError as exc:
            self.call_from_thread(self._status, f"Scan input error: {exc}")

    @staticmethod
    def _parse_target_spec(spec: str) -> tuple[str, list[int]]:
        if ":" in spec:
            ip_part, raw_ports = spec.split(":", maxsplit=1)
            ports = [int(value.strip()) for value in raw_ports.split(",") if value.strip()]
        else:
            ip_part = spec
            ports = [22, 53, 80, 443, 445, 3389, 8080, 8443]
        ipaddress.ip_address(ip_part.strip())
        valid_ports = [port for port in ports if 1 <= port <= 65535]
        if not valid_ports:
            raise ValueError("no valid ports provided")
        return ip_part.strip(), valid_ports

    def _update_scan_text(self, text: str) -> None:
        self.network_scan_text = text
        self._render_lan_scan()

    def _render_threat_map(self) -> None:
        events = self._filtered_events(self.event_engine.all_events())[-60:]
        countries = ["RU", "CN", "US", "DE", "BR", "IN", "Unknown"]
        country_counts = {country: 0 for country in countries}
        for event in events:
            country_counts[random.choice(countries)] += 1
        table = Table(expand=True)
        table.add_column("Country")
        table.add_column("Attempts")
        table.add_column("Attack Types")
        for country, count in sorted(country_counts.items(), key=lambda x: x[1], reverse=True)[:8]:
            table.add_row(country, f"{count:3d}", random.choice(["Brute Force", "Port Scan", "Malware", "C2"]))
        self.query_one("#threatmap_panel", Static).update(Panel(table, title="THREAT MAP (TEXTUAL GEO DISTRIBUTION)"))

    def _render_lookup(self) -> None:
        matches = self.ti.lookup(self.lookup_term) if self.lookup_term else []
        title = f"IOC LOOKUP: {self.lookup_term}" if self.lookup_term else "IOC LOOKUP (enter term above)"
        if not matches and self.lookup_term:
            body: Text | Table = Text("No IOC matches found.", style="yellow")
        else:
            table = Table(expand=True)
            table.add_column("IOC")
            table.add_column("Reputation")
            table.add_column("Risk")
            table.add_column("Tags")
            table.add_column("Threat Family")
            table.add_column("Campaign")
            for ioc in matches[:12]:
                table.add_row(
                    ioc.value,
                    ioc.reputation,
                    str(ioc.score),
                    ", ".join(ioc.tags) or "-",
                    ioc.malware_family or "-",
                    ioc.campaign or "-",
                )
            body = table
        self.query_one("#lookup_panel", Static).update(Panel(body, title=title))

    def _render_mitre(self) -> None:
        active = set(random.sample(MITRE_TECHNIQUES, k=random.randint(2, min(5, len(MITRE_TECHNIQUES)))))
        table = Table(expand=True)
        table.add_column("Tactic")
        table.add_column("Technique")
        table.add_column("Status")
        tactic_map = [
            ("Execution", "T1059 Command and Scripting Interpreter"),
            ("Persistence", "T1078 Valid Accounts"),
            ("Privilege Escalation", "T1055 Process Injection"),
            ("Credential Access", "T1110 Brute Force"),
            ("Lateral Movement", "T1021 Remote Services"),
            ("Exfiltration", "T1041 Exfiltration Over C2 Channel"),
        ]
        for tactic, technique in tactic_map:
            status = "[red]ACTIVE[/]" if technique in active else "[green]OBSERVED[/]"
            table.add_row(tactic, technique, status)
        self.query_one("#mitre_panel", Static).update(Panel(table, title="MITRE ATT&CK MAPPING"))

    def _render_logs(self) -> None:
        log_widget = self.query_one("#log_view", Log)
        log_widget.clear()
        for line in self.log_parser.tail(keyword=self.filter_term, limit=80):
            log_widget.write_line(line)

    def _render_processes(self) -> None:
        processes = self.process_monitor.snapshot(limit=15)
        table = Table(expand=True)
        table.add_column("PID")
        table.add_column("User")
        table.add_column("CPU")
        table.add_column("Mem(MB)")
        table.add_column("PPID")
        table.add_column("Exe")
        table.add_column("Net")
        table.add_column("Indicator")
        for proc in processes:
            indicator = proc.indicator if proc.suspicious else "-"
            style = "red" if proc.suspicious else "white"
            table.add_row(
                str(proc.pid),
                proc.user,
                f"{proc.cpu_percent:4.1f}%",
                f"{proc.memory_mb:6.1f}",
                str(proc.parent_pid),
                proc.executable,
                proc.network_activity,
                f"[{style}]{indicator}[/]",
            )
        self.query_one("#process_panel", Static).update(Panel(table, title="PROCESS MONITOR"))

    def _render_timeline_analytics(self) -> None:
        events = self._filtered_events(self.event_engine.all_events())
        panel = Table.grid(expand=True)
        panel.add_column()
        panel.add_column()

        timeline_lines = [f"{entry.timestamp:%H:%M:%S} {entry.text}" for entry in list(self.timeline)[-14:]]
        timeline_text = "\n".join(timeline_lines) if timeline_lines else "No incidents yet."

        analytics_lines: list[str] = ["Top attacking IPs"]
        for ip, count in top_attacking_ips(events):
            analytics_lines.append(f"{ip:16} {_bar(min(count * 12, 100), width=12)} {count}")
        analytics_lines.append("")
        analytics_lines.append("Targeted destinations")
        for dst, count in targeted_destinations(events):
            analytics_lines.append(f"{dst:16} {_bar(min(count * 12, 100), width=12)} {count}")
        analytics_lines.append("")
        analytics_lines.append("Alerts by severity")
        for sev, count in alerts_by_severity(events):
            analytics_lines.append(f"{sev:10} {_bar(min(count * 8, 100), width=12)} {count}")

        panel.add_row(
            Panel(timeline_text, title="INCIDENT TIMELINE"),
            Panel("\n".join(analytics_lines), title="ANALYTICS"),
        )
        self.query_one("#timeline_panel", Static).update(panel)

    def _status(self, text: str) -> None:
        host = socket.gethostname()
        stamp = datetime.now().strftime("%H:%M:%S")
        pause = "PAUSED" if self.paused else "LIVE"
        self.query_one("#status", Static).update(
            f"[cyan]{stamp}[/]  [{ 'red' if self.paused else 'green' }]{pause}[/]  host={host}  "
            f"filter='{self.filter_term}'  sort={self.sort_mode}  export={self.export_format.upper()}  {text}"
        )
