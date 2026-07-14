from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
import ipaddress
import socket
from typing import Iterable

import psutil

from soc_dashboard.models import ConnectionRecord


class NetworkMonitor:
    COMMON_SCAN_PORTS = (22, 53, 80, 135, 139, 443, 445, 3389, 8080, 8443)

    def snapshot(self) -> dict[str, int | float | list[ConnectionRecord]]:
        raw_conns = psutil.net_connections(kind="inet")
        active = len(raw_conns)
        dns = 0
        http = 0
        ssh = 0
        tls = 0
        internal = 0
        external = 0
        open_ports: set[int] = set()
        service_ids: set[int] = set()
        connections: list[ConnectionRecord] = []

        for conn in raw_conns:
            laddr = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "-"
            raddr = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "-"
            dst_port = conn.raddr.port if conn.raddr else conn.laddr.port if conn.laddr else 0
            state = conn.status
            proto = "TCP" if conn.type == socket.SOCK_STREAM else "UDP"
            encrypted = dst_port in {443, 8443}

            if conn.status == "LISTEN" and conn.laddr:
                open_ports.add(conn.laddr.port)
                if conn.pid:
                    service_ids.add(conn.pid)
            if dst_port == 53:
                dns += 1
            if dst_port in {80, 8080}:
                http += 1
            if dst_port == 22:
                ssh += 1
            if dst_port in {443, 8443}:
                tls += 1
            if conn.raddr:
                try:
                    if ipaddress.ip_address(conn.raddr.ip).is_private:
                        internal += 1
                    else:
                        external += 1
                except ValueError:
                    pass

            if len(connections) < 20:
                connections.append(
                    ConnectionRecord(
                        protocol=proto,
                        source=laddr,
                        destination=raddr,
                        destination_port=dst_port,
                        state=state,
                        encrypted=encrypted,
                    )
                )

        return {
            "active_connections": active,
            "dns_requests": dns,
            "http_requests": http,
            "ssh_sessions": ssh,
            "tls_connections": tls,
            "internal_traffic": internal,
            "external_traffic": external,
            "open_ports": len(open_ports),
            "listening_services": len(service_ids),
            "connections": connections,
        }

    def local_ipv4(self) -> str:
        for iface_addrs in psutil.net_if_addrs().values():
            for addr in iface_addrs:
                if addr.family == socket.AF_INET and addr.address != "127.0.0.1":
                    return addr.address
        return "127.0.0.1"

    def local_subnet_cidr(self) -> str:
        ip = self.local_ipv4()
        network = ipaddress.ip_network(f"{ip}/24", strict=False)
        return str(network)

    def discover_subnet_hosts(
        self,
        subnet_cidr: str | None = None,
        max_hosts: int = 64,
        timeout: float = 0.15,
    ) -> list[str]:
        network = ipaddress.ip_network(subnet_cidr or self.local_subnet_cidr(), strict=False)
        candidates = [str(host) for host in network.hosts() if str(host) != self.local_ipv4()][:max_hosts]
        alive: list[str] = []

        def probe(ip: str) -> str | None:
            for port in self.COMMON_SCAN_PORTS:
                if self._is_port_open(ip, port, timeout):
                    return ip
            return None

        with ThreadPoolExecutor(max_workers=64) as pool:
            futures = [pool.submit(probe, ip) for ip in candidates]
            for fut in as_completed(futures):
                value = fut.result()
                if value:
                    alive.append(value)
        return sorted(set(alive), key=lambda raw: tuple(int(x) for x in raw.split(".")))

    def scan_ports(
        self,
        target_ip: str,
        ports: Iterable[int] | None = None,
        timeout: float = 0.2,
    ) -> list[tuple[int, str]]:
        port_list = list(ports or self.COMMON_SCAN_PORTS)
        open_ports: list[tuple[int, str]] = []
        for port in port_list:
            if self._is_port_open(target_ip, port, timeout):
                service = self._port_to_service(port)
                open_ports.append((port, service))
        return open_ports

    @staticmethod
    def _port_to_service(port: int) -> str:
        return {
            22: "ssh",
            53: "dns",
            80: "http",
            443: "https",
            445: "smb",
            3389: "rdp",
            8080: "http-alt",
            8443: "https-alt",
        }.get(port, "unknown")

    @staticmethod
    def _is_port_open(ip: str, port: int, timeout: float) -> bool:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        try:
            return sock.connect_ex((ip, port)) == 0
        except OSError:
            return False
        finally:
            sock.close()

    @staticmethod
    def ascii_topology() -> str:
        return (
            "            INTERNET\n"
            "                |\n"
            "          [Firewall]\n"
            "                |\n"
            "     +----------+-----------+\n"
            "     |                      |\n"
            " [Web Server]         [VPN Gateway]\n"
            "     |                      |\n"
            "     +----------+-----------+\n"
            "                |\n"
            "           Internal LAN"
        )
