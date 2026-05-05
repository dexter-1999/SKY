"""Local network discovery utilities for SkyGuard."""

from __future__ import annotations

import ipaddress
import re
import socket
import subprocess
from dataclasses import dataclass, asdict
from typing import Any


class LocalNetworkError(RuntimeError):
    """Raised when SkyGuard cannot detect the local network range."""


@dataclass(slots=True)
class LocalNetwork:
    ip_address: str
    subnet_mask: str
    cidr: str
    gateway: str
    adapter: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class LocalNetworkDetector:
    """Detects the active IPv4 LAN range from Windows network configuration."""

    @classmethod
    def detect(cls) -> LocalNetwork:
        detected = cls._from_ipconfig()
        if detected:
            return detected
        return cls._fallback_private_network()

    @classmethod
    def discover_known_hosts(cls, network: LocalNetwork) -> list[str]:
        """Returns likely active LAN hosts from gateway, local IP, and ARP cache."""

        hosts = {network.ip_address}
        if network.gateway:
            hosts.add(network.gateway)

        try:
            cidr = ipaddress.ip_network(network.cidr, strict=False)
        except ValueError:
            cidr = None

        try:
            result = subprocess.run(
                ["arp", "-a"],
                capture_output=True,
                text=True,
                errors="ignore",
                check=False,
            )
            for match in re.finditer(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", result.stdout):
                ip_text = match.group(0)
                try:
                    ip_obj = ipaddress.ip_address(ip_text)
                except ValueError:
                    continue
                if ip_obj.is_loopback or ip_obj.is_multicast or ip_obj.is_link_local:
                    continue
                if cidr and ip_obj not in cidr:
                    continue
                if cidr and ip_obj in {cidr.network_address, cidr.broadcast_address}:
                    continue
                hosts.add(ip_text)
        except OSError:
            pass

        return sorted(hosts, key=lambda value: tuple(int(part) for part in value.split(".")))

    @staticmethod
    def _from_ipconfig() -> LocalNetwork | None:
        try:
            result = subprocess.run(
                ["ipconfig"],
                capture_output=True,
                text=True,
                errors="ignore",
                check=False,
            )
        except OSError:
            return None

        output = result.stdout
        if not output.strip():
            return None

        blocks = re.split(r"\r?\n\r?\n", output)
        candidates: list[LocalNetwork] = []
        for block in blocks:
            ip_match = re.search(r"IPv4[^\r\n:]*:\s*([0-9.]+)", block, re.IGNORECASE)
            mask_match = re.search(r"Subnet Mask[^\r\n:]*:\s*([0-9.]+)", block, re.IGNORECASE)
            if not ip_match or not mask_match:
                continue

            ip_text = ip_match.group(1).strip()
            mask_text = mask_match.group(1).strip()
            try:
                interface = ipaddress.IPv4Interface(f"{ip_text}/{mask_text}")
            except ValueError:
                continue

            ip_obj = interface.ip
            if ip_obj.is_loopback or ip_obj.is_link_local or ip_obj.is_multicast:
                continue

            gateway = ""
            gateway_match = re.search(r"Default Gateway[^\r\n:]*:\s*([0-9.]+)", block, re.IGNORECASE)
            if gateway_match:
                gateway = gateway_match.group(1).strip()

            adapter = "Network Adapter"
            for line in block.splitlines():
                clean_line = line.strip()
                if clean_line.endswith(":") and "adapter" in clean_line.lower():
                    adapter = clean_line.rstrip(":")
                    break
            candidates.append(
                LocalNetwork(
                    ip_address=ip_text,
                    subnet_mask=mask_text,
                    cidr=str(interface.network),
                    gateway=gateway,
                    adapter=adapter,
                )
            )

        private = [network for network in candidates if ipaddress.ip_address(network.ip_address).is_private]
        with_gateway = [network for network in private if network.gateway]
        if with_gateway:
            return with_gateway[0]
        if private:
            return private[0]
        return candidates[0] if candidates else None

    @staticmethod
    def _fallback_private_network() -> LocalNetwork:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.connect(("8.8.8.8", 80))
                ip_text = sock.getsockname()[0]
        except OSError as exc:
            raise LocalNetworkError("Could not detect the local IPv4 network.") from exc

        try:
            ip_obj = ipaddress.ip_address(ip_text)
        except ValueError as exc:
            raise LocalNetworkError("Detected local IP address is invalid.") from exc

        if not ip_obj.is_private:
            raise LocalNetworkError("Detected IP is not a private local network address.")

        network = ipaddress.IPv4Interface(f"{ip_text}/24").network
        return LocalNetwork(
            ip_address=ip_text,
            subnet_mask="255.255.255.0",
            cidr=str(network),
            gateway="",
            adapter="Detected active adapter",
        )
