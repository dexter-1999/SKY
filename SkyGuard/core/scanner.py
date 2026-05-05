"""Network scanning helpers built on top of python-nmap."""

from __future__ import annotations

import re
from dataclasses import dataclass, asdict
from typing import Any

import nmap


class NetworkScanError(RuntimeError):
    """Raised when a network scan cannot be completed."""


_TARGET_PATTERN = re.compile(r"^[A-Za-z0-9.\-_/,: ]+$")
_NMAP_SEARCH_PATHS = (
    "nmap",
    r"C:\Program Files (x86)\Nmap\nmap.exe",
    r"C:\Program Files\Nmap\nmap.exe",
)
_PORT_PATTERN = re.compile(r"^[0-9,\- ]+$")

SCAN_PROFILES = {
    "fast": {
        "name": "Fast",
        "description": "Top 100 TCP ports with light service detection.",
        "arguments": "-sT -sV --version-light -T4 -Pn --top-ports 100 --max-retries 2",
        "timeout": 120,
    },
    "balanced": {
        "name": "Balanced",
        "description": "Top 1000 TCP ports with reliable service detection.",
        "arguments": "-sT -sV --version-light -T3 -Pn --top-ports 1000 --max-retries 3",
        "timeout": 240,
    },
    "accurate": {
        "name": "Accurate",
        "description": "Top 1000 TCP ports with full version probes.",
        "arguments": "-sT -sV --version-all -T3 -Pn --top-ports 1000 --max-retries 3",
        "timeout": 420,
    },
    "full_tcp": {
        "name": "Full TCP",
        "description": "All 65535 TCP ports with light service detection. This can take a long time.",
        "arguments": "-sT -sV --version-light -T3 -Pn -p 1-65535 --max-retries 2",
        "timeout": 1800,
    },
}


@dataclass(slots=True)
class NetworkService:
    host: str
    hostname: str
    protocol: str
    port: int
    state: str
    service: str
    product: str
    version: str
    extra_info: str
    cpe: str
    confidence: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class NetworkScanner:
    """Runs version-detection scans and normalizes Nmap output."""

    def __init__(
        self,
        profile: str = "fast",
        ports: str = "",
        arguments: str | None = None,
        timeout: int | None = None,
    ) -> None:
        selected = SCAN_PROFILES.get(profile, SCAN_PROFILES["fast"])
        self.profile_key = profile if profile in SCAN_PROFILES else "fast"
        self.profile_name = selected["name"]
        self.ports = self._validate_ports(ports)
        base_arguments = arguments or selected["arguments"]
        self.arguments = self._with_custom_ports(base_arguments, self.ports)
        self.timeout = timeout or int(selected["timeout"])

    @classmethod
    def profiles(cls) -> dict[str, dict[str, str | int]]:
        return SCAN_PROFILES.copy()

    @classmethod
    def profile_names(cls) -> list[tuple[str, str]]:
        return [(key, str(value["name"])) for key, value in SCAN_PROFILES.items()]

    @classmethod
    def profile_description(cls, profile: str) -> str:
        selected = SCAN_PROFILES.get(profile, SCAN_PROFILES["fast"])
        return str(selected["description"])

    def scan(self, target: str) -> dict[str, Any]:
        target = self._validate_target(target)

        try:
            scanner = nmap.PortScanner(nmap_search_path=_NMAP_SEARCH_PATHS)
            scanner.scan(hosts=target, arguments=self.arguments, timeout=self.timeout)
        except nmap.PortScannerError as exc:
            raise NetworkScanError(
                "Nmap is not available. Install Nmap or add nmap.exe to PATH."
            ) from exc
        except Exception as exc:
            raise NetworkScanError(f"Network scan failed: {exc}") from exc

        services: list[NetworkService] = []
        host_states: list[dict[str, str]] = []
        for host in scanner.all_hosts():
            hostname = self._hostname_for(scanner, host)
            host_states.append(
                {
                    "host": host,
                    "hostname": hostname,
                    "state": scanner[host].state(),
                }
            )
            for protocol in scanner[host].all_protocols():
                for port in sorted(scanner[host][protocol].keys()):
                    raw = scanner[host][protocol][port]
                    if raw.get("state", "") != "open":
                        continue
                    services.append(
                        NetworkService(
                            host=host,
                            hostname=hostname,
                            protocol=protocol.upper(),
                            port=int(port),
                            state=raw.get("state", ""),
                            service=raw.get("name", ""),
                            product=raw.get("product", ""),
                            version=raw.get("version", ""),
                            extra_info=raw.get("extrainfo", ""),
                            cpe=raw.get("cpe", ""),
                            confidence=str(raw.get("conf", "")),
                        )
                    )

        return {
            "target": target,
            "profile": self.profile_name,
            "scan_arguments": self.arguments,
            "hosts": scanner.all_hosts(),
            "host_states": host_states,
            "nmap_command": scanner.command_line(),
            "scan_stats": scanner.scanstats(),
            "services": [service.to_dict() for service in services],
            "findings": self._build_findings(services),
        }

    @staticmethod
    def _validate_target(target: str) -> str:
        cleaned = target.strip()
        if not cleaned:
            raise NetworkScanError("Enter an IP address, hostname, or IP range to scan.")
        if len(cleaned) > 255 or not _TARGET_PATTERN.match(cleaned):
            raise NetworkScanError("Target contains unsupported characters.")
        return cleaned

    @staticmethod
    def _validate_ports(ports: str) -> str:
        cleaned = ports.strip()
        if not cleaned:
            return ""
        if len(cleaned) > 80 or not _PORT_PATTERN.match(cleaned):
            raise NetworkScanError("Ports must use numbers, commas, and ranges only, e.g. 22,80,443 or 1-1000.")
        for part in cleaned.replace(" ", "").split(","):
            if not part:
                raise NetworkScanError("Ports contain an empty value.")
            if "-" in part:
                if part.count("-") != 1:
                    raise NetworkScanError("Port ranges must use a single dash, e.g. 1-1000.")
                start_text, end_text = part.split("-", 1)
                if not start_text or not end_text:
                    raise NetworkScanError("Port ranges must include a start and end value.")
                start, end = int(start_text), int(end_text)
                if start > end:
                    raise NetworkScanError("Port ranges must be in ascending order.")
                values = (start, end)
            else:
                values = (int(part),)
            if any(value < 1 or value > 65535 for value in values):
                raise NetworkScanError("Ports must be between 1 and 65535.")
        return cleaned.replace(" ", "")

    @staticmethod
    def _with_custom_ports(arguments: str, ports: str) -> str:
        if not ports:
            return arguments
        cleaned_parts: list[str] = []
        skip_next = False
        for part in arguments.split():
            if skip_next:
                skip_next = False
                continue
            if part == "-p":
                skip_next = True
                continue
            if part.startswith("-p") and len(part) > 2:
                continue
            if part == "--top-ports":
                skip_next = True
                continue
            cleaned_parts.append(part)
        cleaned_parts.extend(["-p", ports])
        return " ".join(cleaned_parts)

    @staticmethod
    def _hostname_for(scanner: nmap.PortScanner, host: str) -> str:
        hostnames = scanner[host].hostnames()
        if not hostnames:
            return ""
        return hostnames[0].get("name", "")

    @staticmethod
    def _build_findings(services: list[NetworkService]) -> list[dict[str, str]]:
        findings: list[dict[str, str]] = []
        watched_ports = {
            21: "FTP service is exposed and should be reviewed for encrypted alternatives.",
            23: "Telnet service is exposed; Telnet transmits data without encryption.",
            139: "NetBIOS service is exposed and may increase internal network attack surface.",
            445: "SMB service is exposed and should be restricted to trusted networks.",
            3306: "MySQL service is exposed and should usually be limited to trusted hosts.",
            3389: "Remote Desktop service is exposed and should be tightly access controlled.",
            5432: "PostgreSQL service is exposed and should usually be limited to trusted hosts.",
            5900: "VNC service is exposed and should be restricted and strongly authenticated.",
            6379: "Redis service is exposed and should not be internet-accessible without controls.",
            27017: "MongoDB service is exposed and should be restricted to trusted networks.",
        }

        for service in services:
            if service.state != "open":
                continue
            if service.port in watched_ports:
                findings.append(
                    {
                        "source": "Network Scan",
                        "severity": "Medium",
                        "title": f"Exposed {service.service or service.port} service on {service.host}:{service.port}",
                        "evidence": watched_ports[service.port],
                    }
                )
            elif service.product or service.version:
                findings.append(
                    {
                        "source": "Network Scan",
                        "severity": "Low",
                        "title": f"Version information exposed on {service.host}:{service.port}",
                        "evidence": f"{service.service} {service.product} {service.version}".strip(),
                    }
                )

        return findings
