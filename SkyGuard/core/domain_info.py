"""HTTP and domain inspection helpers."""

from __future__ import annotations

from dataclasses import dataclass, asdict
from typing import Any
from urllib.parse import urlparse

import requests


class DomainScanError(RuntimeError):
    """Raised when a domain scan cannot be completed."""


SECURITY_HEADERS = {
    "Strict-Transport-Security": "Helps enforce HTTPS on supported browsers.",
    "Content-Security-Policy": "Helps reduce cross-site scripting and data injection risk.",
    "X-Frame-Options": "Helps reduce clickjacking risk on older browsers.",
    "X-Content-Type-Options": "Helps prevent MIME sniffing.",
    "Referrer-Policy": "Controls referrer data leakage.",
    "Permissions-Policy": "Restricts powerful browser features.",
}

INFO_EXPOSURE_HEADERS = ("Server", "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version")


@dataclass(slots=True)
class DomainScanResult:
    url: str
    final_url: str
    status_code: int
    reason: str
    headers: dict[str, str]
    missing_security_headers: list[str]
    exposed_info_headers: dict[str, str]
    findings: list[dict[str, str]]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class DomainScanner:
    """Fetches HTTP metadata and produces evidence-based findings."""

    def __init__(self, timeout: int = 15) -> None:
        self.timeout = timeout

    def scan(self, url: str) -> dict[str, Any]:
        normalized_url = self._normalize_url(url)

        try:
            response = requests.get(
                normalized_url,
                timeout=self.timeout,
                allow_redirects=True,
                headers={"User-Agent": "SkyGuard/1.0 Security Scanner"},
            )
        except requests.exceptions.Timeout as exc:
            raise DomainScanError("The request timed out while fetching the domain.") from exc
        except requests.exceptions.RequestException as exc:
            raise DomainScanError(f"Domain request failed: {exc}") from exc

        headers = {key: value for key, value in response.headers.items()}
        lower_headers = {key.lower(): key for key in headers}
        missing = [
            name for name in SECURITY_HEADERS
            if name.lower() not in lower_headers
        ]
        exposed = {}
        for name in INFO_EXPOSURE_HEADERS:
            original = lower_headers.get(name.lower())
            if original and headers[original].strip():
                exposed[original] = headers[original]

        result = DomainScanResult(
            url=normalized_url,
            final_url=response.url,
            status_code=response.status_code,
            reason=response.reason,
            headers=headers,
            missing_security_headers=missing,
            exposed_info_headers=exposed,
            findings=self._build_findings(response.status_code, missing, exposed),
        )
        return result.to_dict()

    @staticmethod
    def _normalize_url(url: str) -> str:
        cleaned = url.strip()
        if not cleaned:
            raise DomainScanError("Enter a URL to scan.")
        if "://" not in cleaned:
            cleaned = f"https://{cleaned}"

        parsed = urlparse(cleaned)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise DomainScanError("Enter a valid HTTP or HTTPS URL.")
        return cleaned

    @staticmethod
    def _build_findings(
        status_code: int,
        missing_headers: list[str],
        exposed_headers: dict[str, str],
    ) -> list[dict[str, str]]:
        findings: list[dict[str, str]] = []

        for header in missing_headers:
            severity = "Medium" if header in {"Strict-Transport-Security", "Content-Security-Policy"} else "Low"
            findings.append(
                {
                    "source": "Domain Scan",
                    "severity": severity,
                    "title": f"Missing security header: {header}",
                    "evidence": SECURITY_HEADERS[header],
                }
            )

        for header, value in exposed_headers.items():
            findings.append(
                {
                    "source": "Domain Scan",
                    "severity": "Low",
                    "title": f"Information disclosure via {header} header",
                    "evidence": f"{header}: {value}",
                }
            )

        if 500 <= status_code <= 599:
            findings.append(
                {
                    "source": "Domain Scan",
                    "severity": "Medium",
                    "title": "Server returned a 5xx response",
                    "evidence": f"Observed HTTP status code {status_code}.",
                }
            )

        return findings
