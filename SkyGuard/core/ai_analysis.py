"""AI-assisted report generation for SkyGuard."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any


SEVERITY_WEIGHTS = {
    "Low": 8,
    "Medium": 18,
    "High": 30,
    "Critical": 45,
}


class AIAnalysisError(RuntimeError):
    """Raised when AI analysis fails."""


class AIAnalysisEngine:
    """Builds local reports and optionally refines them through Gemini."""

    def __init__(self, model_name: str = "auto") -> None:
        self.model_name = model_name
        self.active_model_name = ""
        self.project_root = Path(__file__).resolve().parents[1]
        self.env_path = self.project_root / ".env"
        self.api_key = os.getenv("GEMINI_API_KEY") or os.getenv("GOOGLE_API_KEY") or self._load_env_key()

    def has_api_key(self) -> bool:
        return bool(self.api_key)

    def set_api_key(self, api_key: str) -> None:
        cleaned = api_key.strip()
        if not cleaned:
            raise AIAnalysisError("Gemini API key is empty.")
        self.api_key = cleaned

    def save_api_key(self, api_key: str) -> None:
        self.set_api_key(api_key)
        lines = []
        if self.env_path.exists():
            lines = self.env_path.read_text(encoding="utf-8").splitlines()

        updated = False
        next_lines: list[str] = []
        for line in lines:
            if line.startswith("GEMINI_API_KEY="):
                next_lines.append(f"GEMINI_API_KEY={self.api_key}")
                updated = True
            else:
                next_lines.append(line)

        if not updated:
            next_lines.append(f"GEMINI_API_KEY={self.api_key}")

        self.env_path.write_text("\n".join(next_lines).strip() + "\n", encoding="utf-8")

    def test_connection(self) -> str:
        if not self.api_key:
            raise AIAnalysisError("Gemini API key is not configured.")

        try:
            import google.generativeai as genai

            genai.configure(api_key=self.api_key)
            text, model_name = self._generate_with_available_model(
                genai,
                "Reply with SKYGUARD_OK only. This is an API connectivity test.",
            )
        except Exception as exc:
            raise AIAnalysisError(f"Gemini API connection failed: {exc}") from exc

        if not text:
            raise AIAnalysisError("Gemini API returned an empty response.")
        return f"Gemini API connected successfully using {model_name}."

    def generate_report(
        self,
        network_data: dict[str, Any] | None,
        domain_data: dict[str, Any] | None,
        use_ai: bool = True,
    ) -> str:
        data = self._combined_data(network_data, domain_data)
        local_report = self._local_report(data)

        if not use_ai or not self.api_key:
            note = "Gemini API key not configured; generated with SkyGuard local analysis."
            return f"{local_report}\n\nAnalysis Note: {note}\n"

        prompt = self._build_prompt(data, local_report)
        try:
            import google.generativeai as genai

            genai.configure(api_key=self.api_key)
            text, _model_name = self._generate_with_available_model(genai, prompt)
        except Exception as exc:
            raise AIAnalysisError(f"AI analysis failed: {exc}") from exc

        if not text:
            raise AIAnalysisError("AI analysis returned an empty response.")
        return text

    @staticmethod
    def risk_score(findings: list[dict[str, Any]]) -> int:
        score = sum(SEVERITY_WEIGHTS.get(str(finding.get("severity", "Low")), 8) for finding in findings)
        return max(0, min(score, 100))

    def _combined_data(
        self,
        network_data: dict[str, Any] | None,
        domain_data: dict[str, Any] | None,
    ) -> dict[str, Any]:
        findings: list[dict[str, Any]] = []
        if network_data:
            findings.extend(network_data.get("findings", []))
        if domain_data:
            findings.extend(domain_data.get("findings", []))

        return {
            "network_scan": network_data,
            "domain_scan": domain_data,
            "findings": findings,
            "risk_score": self.risk_score(findings),
        }

    def _load_env_key(self) -> str:
        if not self.env_path.exists():
            return ""
        for line in self.env_path.read_text(encoding="utf-8").splitlines():
            clean = line.strip()
            if not clean or clean.startswith("#") or "=" not in clean:
                continue
            key, value = clean.split("=", 1)
            if key.strip() in {"GEMINI_API_KEY", "GOOGLE_API_KEY"}:
                return value.strip().strip('"').strip("'")
        return ""

    def _generate_with_available_model(self, genai: Any, prompt: str) -> tuple[str, str]:
        last_error: Exception | None = None
        for model_name in self._candidate_model_names(genai):
            try:
                model = genai.GenerativeModel(model_name)
                response = model.generate_content(prompt)
                text = (getattr(response, "text", "") or "").strip()
                self.active_model_name = model_name
                return text, model_name
            except Exception as exc:
                last_error = exc
                message = str(exc).lower()
                if any(token in message for token in ("not found", "not supported", "404", "generatecontent")):
                    continue
                raise

        if last_error:
            raise AIAnalysisError(
                "No Gemini model that supports generateContent was available for this API key. "
                f"Last provider error: {last_error}"
            ) from last_error
        raise AIAnalysisError("No Gemini models were returned by the API.")

    def _candidate_model_names(self, genai: Any) -> list[str]:
        if self.model_name and self.model_name != "auto":
            return [self.model_name]

        preferred = [
            "gemini-2.5-flash",
            "gemini-2.5-pro",
            "gemini-2.0-flash",
            "gemini-2.0-flash-lite",
            "gemini-1.5-flash",
            "gemini-1.5-pro",
            "gemini-pro",
        ]
        fallback = [f"models/{name}" for name in preferred] + preferred
        discovered: list[str] = []

        try:
            for model in genai.list_models():
                methods = set(getattr(model, "supported_generation_methods", []) or [])
                name = str(getattr(model, "name", "") or "")
                lowered = name.lower()
                if not name or "generateContent" not in methods:
                    continue
                if any(skip in lowered for skip in ("embedding", "imagen", "tts", "veo", "aqa")):
                    continue
                discovered.append(name)
        except Exception:
            discovered = []

        def rank(name: str) -> tuple[int, str]:
            lowered = name.lower()
            for index, token in enumerate(preferred):
                if token in lowered:
                    return index, lowered
            return len(preferred), lowered

        ordered = sorted(discovered, key=rank) + fallback
        unique: list[str] = []
        seen: set[str] = set()
        for name in ordered:
            if name not in seen:
                unique.append(name)
                seen.add(name)
        return unique

    def _local_report(self, data: dict[str, Any]) -> str:
        findings = data["findings"]
        risk_score = data["risk_score"]

        lines = [
            "=== SkyGuard Security Report ===",
            "",
            "- Summary",
            self._summary(data),
            "",
            "- Findings",
        ]

        if findings:
            for index, finding in enumerate(findings, start=1):
                lines.extend(
                    [
                        f"{index}. [{finding.get('severity', 'Low')}] {finding.get('title', 'Finding')}",
                        f"   Source: {finding.get('source', 'Unknown')}",
                        f"   Evidence: {finding.get('evidence', 'No evidence provided.')}",
                    ]
                )
        else:
            lines.append("No findings were identified from the collected evidence.")

        lines.extend(
            [
                "",
                "- Risk Assessment",
                f"Risk Score: {risk_score}/100",
                self._risk_label(risk_score),
                "",
                "- Recommendations",
            ]
        )
        lines.extend(self._recommendations(data))
        return "\n".join(lines)

    @staticmethod
    def _summary(data: dict[str, Any]) -> str:
        network = data.get("network_scan")
        domain = data.get("domain_scan")
        parts: list[str] = []

        if network:
            services = network.get("services", [])
            hosts = network.get("hosts", [])
            stats = network.get("scan_stats", {})
            elapsed = stats.get("elapsed")
            elapsed_text = f" in {elapsed}s" if elapsed else ""
            local_network = network.get("local_network") or {}
            local_text = ""
            if local_network:
                local_text = (
                    f" Local network detected as {local_network.get('cidr')} "
                    f"from host IP {local_network.get('ip_address')}. "
                    f"Actual scan target: {local_network.get('scan_target', local_network.get('cidr'))}."
                )
            parts.append(
                f"Network scan used the {network.get('profile', 'selected')} profile, covered "
                f"{len(hosts)} host(s), and found {len(services)} open service record(s){elapsed_text}."
                f"{local_text}"
            )
        if domain:
            parts.append(
                f"Domain scan fetched {domain.get('final_url', domain.get('url'))} "
                f"with HTTP status {domain.get('status_code')}."
            )
        if not parts:
            return "No scan data has been collected yet."
        return " ".join(parts)

    @staticmethod
    def _risk_label(score: int) -> str:
        if score >= 80:
            return "Overall Risk: Critical"
        if score >= 55:
            return "Overall Risk: High"
        if score >= 25:
            return "Overall Risk: Medium"
        if score > 0:
            return "Overall Risk: Low"
        return "Overall Risk: Informational"

    @staticmethod
    def _recommendations(data: dict[str, Any]) -> list[str]:
        recommendations: list[str] = []
        domain = data.get("domain_scan") or {}
        network = data.get("network_scan") or {}

        if domain.get("missing_security_headers"):
            recommendations.append("- Add missing HTTP security headers where compatible with the application.")
        if domain.get("exposed_info_headers"):
            recommendations.append("- Reduce unnecessary server and framework version disclosure in HTTP headers.")
        if network.get("services"):
            recommendations.append("- Review exposed services, restrict access by network policy, and disable unused ports.")
            recommendations.append("- Validate service versions against vendor advisories before making vulnerability claims.")
        if network.get("nmap_command"):
            recommendations.append(f"- Nmap evidence command: {network.get('nmap_command')}")
        if not recommendations:
            recommendations.append("- Continue periodic scanning and compare results against an approved asset inventory.")

        return recommendations

    @staticmethod
    def _build_prompt(data: dict[str, Any], local_report: str) -> str:
        serialized = json.dumps(data, indent=2, ensure_ascii=False)
        return f"""
You are SkyGuard, an AI cybersecurity reporting assistant.

Rules:
- Do not assume vulnerabilities without direct evidence in the provided scan data.
- Keep the analysis technical, accurate, and concise.
- Preserve this exact report structure:

=== SkyGuard Security Report ===
- Summary
- Findings (with severity: Low / Medium / High / Critical)
- Risk Assessment
- Recommendations

Collected evidence:
{serialized}

Baseline deterministic report:
{local_report}
""".strip()
