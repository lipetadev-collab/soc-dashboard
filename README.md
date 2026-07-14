# Threat Intelligence & SOC Dashboard (ASCII)

Professional terminal-based SOC and threat intelligence dashboard built with Python and Textual.

## Features

- Multi-tab SOC workstation interface in terminal (ASCII/Unicode).
- Live system health, security alerts, threat intel, network activity, process monitor, and incident timeline.
- MITRE ATT&CK mapping and IOC lookup.
- Filter/search controls, keyboard navigation, pause mode, and configurable refresh interval.
- Export support: JSON, CSV, TXT, HTML, Markdown.
- Modular architecture for detection, parsing, IOC storage, alerts, analytics, and plugins.

## Quick Start

```bash
python -m pip install -e .
soc-dashboard
# or: python -m soc_dashboard
```

## Real Network Scanning

- The dashboard includes real local network enumeration and target port scanning features.
- Use only on systems and networks you own or are explicitly authorized to test.
- Open the dedicated `LAN Scan` tab with `0`, then:
  - `n` runs local subnet host discovery
  - submit `target_scan_input` like `192.168.1.20:22,80,443` for targeted checks

## Keyboard Shortcuts

- `q`: Quit
- `p`: Pause/Resume auto-refresh
- `r`: Manual refresh
- `f`: Focus filter input
- `e`: Export snapshot
- `x`: Cycle export format (JSON/CSV/TXT/HTML/MD)
- `s`: Cycle alert sorting mode
- `t`: Toggle theme
- `n`: Scan local subnet for live hosts
- `1-9`: Switch primary tabs
- `0`: Open LAN Scan tab

Network scan input format:

- `192.168.1.20` (uses default common ports)
- `192.168.1.20:22,80,443,3389` (custom ports)

## Architecture

- `ui`: Textual application and widgets.
- `engine`: Event generation, detections, threat intelligence, network and process monitors.
- `models`: Strongly typed dataclasses for all dashboard entities.
- `exporter`: Multi-format data exporter.
- `config`: Config manager with environment overrides.
- `plugins`: Plugin interface for extending detections and feeds.

## Module Coverage

- **SOC Overview**: CPU, RAM, Disk, network throughput, users, sessions, services, uptime.
- **Security Alerts**: timestamp/severity/source/destination/description with color-coded levels.
- **Threat Intelligence**: IOC feeds, reputation score, ASN, geolocation fields, and last observed.
- **Network Monitoring**: traffic counters, active connections, ports/services, ASCII topology graph.
- **Threat Map**: textual distribution of attack origins and attack type trends.
- **IOC Lookup**: interactive IOC search via lookup input.
- **MITRE ATT&CK**: active/observed mapping to ATT&CK techniques.
- **Log Viewer**: multi-source simulated log stream with filtering and auto-scroll.
- **Process Monitor**: PID/user/cpu/memory/ppid/executable/network/suspicious indicators.
- **Incident Timeline & Analytics**: chronological incidents plus bar-style analytics.

## Notes

This project includes simulated security telemetry out-of-the-box for demos and training. Replace generators in the engine modules with real collectors (Zeek, Suricata, Syslog, Windows Events, Wazuh, Falco, SIEM APIs) for production data sources.

## Publish To GitHub

```bash
git remote add origin https://github.com/lipetadev-collab/soc-dashboard.git
git branch -M main
git push -u origin main
```
