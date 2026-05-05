"""Main PyQt6 user interface for SkyGuard."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from PyQt6.QtCore import QObject, QThread, pyqtSignal
from PyQt6.QtGui import QFont
from PyQt6.QtWidgets import (
    QApplication,
    QComboBox,
    QFileDialog,
    QGridLayout,
    QGroupBox,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMessageBox,
    QPushButton,
    QPlainTextEdit,
    QProgressBar,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from core.ai_analysis import AIAnalysisEngine
from core.domain_info import DomainScanner
from core.local_network import LocalNetworkDetector
from core.scanner import NetworkScanner


class TaskWorker(QObject):
    finished = pyqtSignal(object)
    failed = pyqtSignal(str)

    def __init__(self, task) -> None:
        super().__init__()
        self.task = task

    def run(self) -> None:
        try:
            self.finished.emit(self.task())
        except Exception as exc:
            self.failed.emit(str(exc))


class MainWindow(QMainWindow):
    """SkyGuard desktop application window."""

    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("SkyGuard - Security Scanner")
        self.resize(1280, 820)

        self.network_data: dict[str, Any] | None = None
        self.domain_data: dict[str, Any] | None = None
        self.active_threads: list[QThread] = []
        self.active_workers: list[TaskWorker] = []
        self.ai_engine = AIAnalysisEngine()
        self.auto_ai_after_network_scan = False
        self.force_ai_report = False

        self._build_ui()
        self._apply_theme()

    def _build_ui(self) -> None:
        central = QWidget()
        root = QVBoxLayout(central)
        root.setContentsMargins(22, 20, 22, 20)
        root.setSpacing(16)

        header = QLabel("SkyGuard AI Security Platform")
        header.setObjectName("Header")
        root.addWidget(header)

        subtitle = QLabel("Network scanning, domain inspection, and evidence-based AI reporting")
        subtitle.setObjectName("Subtitle")
        root.addWidget(subtitle)

        body = QGridLayout()
        body.setSpacing(16)
        body.addWidget(self._network_section(), 0, 0)
        body.addWidget(self._domain_section(), 1, 0)
        body.addWidget(self._report_section(), 0, 1, 2, 1)
        body.setColumnStretch(0, 3)
        body.setColumnStretch(1, 2)
        body.setRowStretch(0, 3)
        body.setRowStretch(1, 2)
        root.addLayout(body, stretch=1)

        self.status_label = QLabel("Ready")
        self.status_label.setObjectName("Status")
        root.addWidget(self.status_label)

        self.setCentralWidget(central)

    def _network_section(self) -> QGroupBox:
        box = QGroupBox("Network Scan")
        layout = QVBoxLayout(box)
        layout.setSpacing(12)

        controls = QHBoxLayout()
        self.network_input = QLineEdit()
        self.network_input.setPlaceholderText("IP, hostname, or range, e.g. 192.168.1.1 or 192.168.1.0/24")
        self.scan_profile = QComboBox()
        for key, name in NetworkScanner.profile_names():
            self.scan_profile.addItem(name, key)
        self.scan_profile.currentIndexChanged.connect(self._update_scan_hint)
        self.port_input = QLineEdit()
        self.port_input.setPlaceholderText("Ports optional: 22,80,443")
        self.port_input.setMaximumWidth(180)
        self.network_button = QPushButton("Run Nmap Scan")
        self.network_button.clicked.connect(self.run_network_scan)
        self.local_network_button = QPushButton("Scan Local Network + AI Report")
        self.local_network_button.clicked.connect(self.scan_local_network_with_ai_report)
        controls.addWidget(self.network_input, stretch=1)
        controls.addWidget(self.scan_profile)
        controls.addWidget(self.port_input)
        controls.addWidget(self.network_button)
        controls.addWidget(self.local_network_button)
        layout.addLayout(controls)

        self.scan_hint = QLabel()
        self.scan_hint.setObjectName("ScanHint")
        layout.addWidget(self.scan_hint)

        self.network_table = QTableWidget(0, 9)
        self.network_table.setHorizontalHeaderLabels(
            ["Host", "Hostname", "Protocol", "Port", "State", "Service", "Product", "Version", "Confidence"]
        )
        self.network_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.network_table.verticalHeader().setVisible(False)
        self.network_table.setAlternatingRowColors(True)
        self.network_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        layout.addWidget(self.network_table, stretch=1)
        self._update_scan_hint()

        return box

    def _domain_section(self) -> QGroupBox:
        box = QGroupBox("Domain Scan")
        layout = QVBoxLayout(box)
        layout.setSpacing(12)

        controls = QHBoxLayout()
        self.domain_input = QLineEdit()
        self.domain_input.setPlaceholderText("https://example.com")
        self.domain_button = QPushButton("Fetch Domain Info")
        self.domain_button.clicked.connect(self.run_domain_scan)
        controls.addWidget(self.domain_input, stretch=1)
        controls.addWidget(self.domain_button)
        layout.addLayout(controls)

        self.domain_table = QTableWidget(0, 2)
        self.domain_table.setHorizontalHeaderLabels(["Property", "Value"])
        self.domain_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        self.domain_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self.domain_table.verticalHeader().setVisible(False)
        self.domain_table.setAlternatingRowColors(True)
        layout.addWidget(self.domain_table, stretch=1)

        return box

    def _report_section(self) -> QGroupBox:
        box = QGroupBox("AI Report Viewer")
        layout = QVBoxLayout(box)
        layout.setSpacing(12)

        api_controls = QHBoxLayout()
        self.api_key_input = QLineEdit()
        self.api_key_input.setEchoMode(QLineEdit.EchoMode.Password)
        if self.ai_engine.has_api_key():
            self.api_key_input.setPlaceholderText("Gemini API key is configured")
        else:
            self.api_key_input.setPlaceholderText("Paste Gemini API key here")
        self.save_api_key_button = QPushButton("Save Key")
        self.save_api_key_button.clicked.connect(self.save_ai_key)
        self.test_api_button = QPushButton("Test API")
        self.test_api_button.clicked.connect(self.test_ai_connection)
        api_controls.addWidget(self.api_key_input, stretch=1)
        api_controls.addWidget(self.save_api_key_button)
        api_controls.addWidget(self.test_api_button)
        layout.addLayout(api_controls)

        self.ai_status_label = QLabel(self._ai_status_text())
        self.ai_status_label.setObjectName("AIStatus")
        layout.addWidget(self.ai_status_label)

        controls = QHBoxLayout()
        self.report_button = QPushButton("Generate Report")
        self.report_button.clicked.connect(self.generate_report)
        self.export_button = QPushButton("Export Report to TXT")
        self.export_button.clicked.connect(self.export_report)
        controls.addWidget(self.report_button)
        controls.addWidget(self.export_button)
        controls.addStretch(1)
        layout.addLayout(controls)

        self.risk_label = QLabel("Risk Score: 0/100")
        self.risk_label.setObjectName("RiskLabel")
        layout.addWidget(self.risk_label)

        self.progress = QProgressBar()
        self.progress.setRange(0, 0)
        self.progress.hide()
        layout.addWidget(self.progress)

        self.report_view = QPlainTextEdit()
        self.report_view.setReadOnly(True)
        self.report_view.setPlaceholderText("Run scans, then generate a SkyGuard security report.")
        self.report_view.setLineWrapMode(QPlainTextEdit.LineWrapMode.WidgetWidth)
        layout.addWidget(self.report_view, stretch=1)

        return box

    def run_network_scan(self) -> None:
        target = self.network_input.text().strip()
        if not target:
            self._show_error("Network Scan", "Enter an IP address, hostname, or range.")
            return
        self.auto_ai_after_network_scan = False
        profile = self.scan_profile.currentData()
        ports = self.port_input.text().strip()
        self._set_busy("Running Nmap version scan...", True)
        self.network_button.setEnabled(False)
        self.local_network_button.setEnabled(False)
        self._show_network_message(
            "Scanning with Nmap...",
            f"Profile: {self.scan_profile.currentText()}. Custom ports: {ports or 'profile default'}.",
        )
        self._run_task(
            lambda: NetworkScanner(profile=profile, ports=ports).scan(target),
            self._on_network_result,
            lambda message: self._on_task_error("Network Scan", message, self.network_button),
        )

    def scan_local_network_with_ai_report(self) -> None:
        typed_key = self.api_key_input.text().strip()
        if typed_key:
            try:
                self.ai_engine.set_api_key(typed_key)
                self.ai_status_label.setText(self._ai_status_text())
            except Exception as exc:
                self._show_error("AI Report", str(exc))
                return

        if not self.ai_engine.has_api_key():
            self._show_error("AI Report", "Add or save a Gemini API key before running the AI local-network report.")
            return

        self.auto_ai_after_network_scan = True
        self.force_ai_report = True
        self._set_busy("Detecting local network and starting Nmap scan...", True)
        self.network_button.setEnabled(False)
        self.local_network_button.setEnabled(False)
        self._show_network_message("Detecting local network...", "SkyGuard is reading your Windows IPv4 network settings.")
        self._run_task(
            self._detect_and_scan_local_network,
            self._on_network_result,
            lambda message: self._on_task_error("Local Network Scan", message, self.local_network_button),
        )

    def run_domain_scan(self) -> None:
        url = self.domain_input.text().strip()
        if not url:
            self._show_error("Domain Scan", "Enter a URL to scan.")
            return
        self._set_busy("Fetching domain information...", True)
        self.domain_button.setEnabled(False)
        self._run_task(
            lambda: DomainScanner().scan(url),
            self._on_domain_result,
            lambda message: self._on_task_error("Domain Scan", message, self.domain_button),
        )

    def generate_report(self) -> None:
        if not self.network_data and not self.domain_data:
            self._show_error("AI Report", "Run at least one scan before generating a report.")
            return

        typed_key = self.api_key_input.text().strip()
        if typed_key:
            try:
                self.ai_engine.set_api_key(typed_key)
                self.ai_status_label.setText(self._ai_status_text())
            except Exception as exc:
                self._show_error("AI Report", str(exc))
                return

        self._set_busy("Generating security report...", True)
        self.report_button.setEnabled(False)
        self.local_network_button.setEnabled(False)
        self._run_task(
            lambda: self.ai_engine.generate_report(self.network_data, self.domain_data),
            self._on_report_result,
            lambda message: self._on_report_error(message),
        )

    def export_report(self) -> None:
        report = self.report_view.toPlainText().strip()
        if not report:
            self._show_error("Export Report", "Generate a report before exporting.")
            return

        path, _ = QFileDialog.getSaveFileName(
            self,
            "Export SkyGuard Report",
            str(Path.home() / "skyguard_report.txt"),
            "Text Files (*.txt)",
        )
        if not path:
            return

        try:
            Path(path).write_text(report, encoding="utf-8")
        except OSError as exc:
            self._show_error("Export Report", f"Could not write report: {exc}")
            return
        self.status_label.setText(f"Report exported to {path}")

    def save_ai_key(self) -> None:
        api_key = self.api_key_input.text().strip()
        if not api_key:
            self._show_error("AI Settings", "Paste the Gemini API key before saving.")
            return
        try:
            self.ai_engine.save_api_key(api_key)
        except Exception as exc:
            self._show_error("AI Settings", str(exc))
            return
        self.api_key_input.clear()
        self.api_key_input.setPlaceholderText("Gemini API key is configured")
        self.ai_status_label.setText(self._ai_status_text())
        self.status_label.setText("Gemini API key saved locally in .env.")

    def test_ai_connection(self) -> None:
        typed_key = self.api_key_input.text().strip()
        if typed_key:
            try:
                self.ai_engine.set_api_key(typed_key)
            except Exception as exc:
                self._show_error("AI Settings", str(exc))
                return
        if not self.ai_engine.has_api_key():
            self._show_error("AI Settings", "Paste or save a Gemini API key before testing.")
            return

        self._set_busy("Testing Gemini API connection...", True)
        self.test_api_button.setEnabled(False)
        self._run_task(
            self.ai_engine.test_connection,
            self._on_ai_test_result,
            self._on_ai_test_error,
        )

    def _run_task(self, task, on_success, on_failure) -> None:
        thread = QThread(self)
        worker = TaskWorker(task)
        worker.moveToThread(thread)
        thread._skyguard_worker = worker

        thread.started.connect(worker.run)
        worker.finished.connect(on_success)
        worker.failed.connect(on_failure)
        worker.finished.connect(thread.quit)
        worker.failed.connect(thread.quit)
        worker.finished.connect(worker.deleteLater)
        worker.failed.connect(worker.deleteLater)
        thread.finished.connect(lambda: self._cleanup_thread(thread))
        self.active_threads.append(thread)
        self.active_workers.append(worker)
        thread.start()

    def _detect_and_scan_local_network(self) -> dict[str, Any]:
        local_network = LocalNetworkDetector.detect()
        known_hosts = LocalNetworkDetector.discover_known_hosts(local_network)
        target = " ".join(known_hosts)
        if not target or len(target) > 250:
            target = local_network.cidr

        common_lan_ports = "22,25,53,80,110,135,139,143,443,445,465,587,993,995,3389,8080,8443"
        scanner = NetworkScanner(profile="fast", ports=common_lan_ports, timeout=180)
        data = scanner.scan(target)
        data["local_network"] = local_network.to_dict()
        data["local_network"]["known_hosts"] = known_hosts
        data["local_network"]["scan_target"] = target
        return data

    def _on_network_result(self, data: dict[str, Any]) -> None:
        self.network_data = data
        local_network = data.get("local_network")
        if local_network:
            self.network_input.setText(local_network.get("cidr", ""))
            self.scan_profile.setCurrentIndex(self.scan_profile.findData("fast"))
        services = data.get("services", [])
        if services:
            self.network_table.setRowCount(len(services))
            for row, service in enumerate(services):
                values = [
                    service.get("host", ""),
                    service.get("hostname", ""),
                    service.get("protocol", ""),
                    str(service.get("port", "")),
                    service.get("state", ""),
                    service.get("service", ""),
                    service.get("product", ""),
                    service.get("version", ""),
                    service.get("confidence", ""),
                ]
                for column, value in enumerate(values):
                    self.network_table.setItem(row, column, QTableWidgetItem(value))
        else:
            states = data.get("host_states", [])
            if states:
                state_text = ", ".join(
                    f"{item.get('host')} is {item.get('state', 'unknown')}" for item in states
                )
            else:
                state_text = "No host response was returned by Nmap."
            self._show_network_message(
                "No open ports detected",
                f"{state_text} Command: {data.get('nmap_command', 'nmap')}",
            )

        self.network_button.setEnabled(True)
        self.local_network_button.setEnabled(True)
        stats = data.get("scan_stats", {})
        elapsed = stats.get("elapsed", "")
        suffix = f" in {elapsed}s" if elapsed else ""
        self._set_busy(f"Real Nmap scan complete: {len(services)} open service(s){suffix}.", False)
        self._refresh_risk_score()
        if self.auto_ai_after_network_scan:
            self.auto_ai_after_network_scan = False
            self._start_ai_report(require_ai=True)

    def _on_domain_result(self, data: dict[str, Any]) -> None:
        self.domain_data = data
        rows: list[tuple[str, str]] = [
            ("URL", data.get("url", "")),
            ("Final URL", data.get("final_url", "")),
            ("HTTP Status", f"{data.get('status_code')} {data.get('reason', '')}".strip()),
            ("Missing Security Headers", ", ".join(data.get("missing_security_headers", [])) or "None detected"),
        ]

        exposed = data.get("exposed_info_headers", {})
        rows.append(("Server Info Exposure", ", ".join(f"{key}: {value}" for key, value in exposed.items()) or "None detected"))

        for key, value in sorted(data.get("headers", {}).items()):
            rows.append((f"Header: {key}", value))

        self.domain_table.setRowCount(len(rows))
        for row, (key, value) in enumerate(rows):
            self.domain_table.setItem(row, 0, QTableWidgetItem(key))
            self.domain_table.setItem(row, 1, QTableWidgetItem(value))

        self.domain_button.setEnabled(True)
        self._set_busy("Domain scan complete.", False)
        self._refresh_risk_score()

    def _on_report_result(self, report: str) -> None:
        self.report_view.setPlainText(report)
        self.report_button.setEnabled(True)
        self.local_network_button.setEnabled(True)
        self.force_ai_report = False
        self._set_busy("Report generated.", False)
        self._refresh_risk_score()

    def _on_report_error(self, message: str) -> None:
        if self.force_ai_report:
            self.report_button.setEnabled(True)
            self.local_network_button.setEnabled(True)
            self.force_ai_report = False
            self._set_busy("Ready", False)
            self._show_error("AI Report", message)
            return
        try:
            report = self.ai_engine.generate_report(self.network_data, self.domain_data, use_ai=False)
            self.report_view.setPlainText(f"{report}\nAI Provider Error: {message}\n")
            self.status_label.setText("Generated local report after AI provider error.")
        except Exception:
            self._show_error("AI Report", message)
        finally:
            self.report_button.setEnabled(True)
            self.local_network_button.setEnabled(True)
            self._set_busy("Ready", False)
            self._refresh_risk_score()

    def _on_ai_test_result(self, message: str) -> None:
        self.test_api_button.setEnabled(True)
        self.ai_status_label.setText(message)
        self._set_busy("Gemini API connection verified.", False)

    def _on_ai_test_error(self, message: str) -> None:
        self.test_api_button.setEnabled(True)
        self._set_busy("Ready", False)
        self._show_error("AI Settings", message)

    def _on_task_error(self, title: str, message: str, button: QPushButton) -> None:
        button.setEnabled(True)
        self.network_button.setEnabled(True)
        self.local_network_button.setEnabled(True)
        self.auto_ai_after_network_scan = False
        self.force_ai_report = False
        self._set_busy("Ready", False)
        self._show_error(title, message)

    def closeEvent(self, event) -> None:
        if self.active_threads:
            QMessageBox.information(
                self,
                "SkyGuard is still working",
                "A scan or AI report is still running. Please wait until it finishes before closing SkyGuard.",
            )
            event.ignore()
            return
        event.accept()

    def _start_ai_report(self, require_ai: bool = False) -> None:
        if not self.network_data and not self.domain_data:
            self._show_error("AI Report", "Run at least one scan before generating a report.")
            return
        if require_ai and not self.ai_engine.has_api_key():
            self._show_error("AI Report", "Gemini API key is required for this report.")
            return

        self.force_ai_report = require_ai
        self._set_busy("Generating AI security report with Gemini...", True)
        self.report_button.setEnabled(False)
        self.local_network_button.setEnabled(False)
        self._run_task(
            lambda: self.ai_engine.generate_report(self.network_data, self.domain_data),
            self._on_report_result,
            lambda message: self._on_report_error(message),
        )

    def _refresh_risk_score(self) -> None:
        findings: list[dict[str, Any]] = []
        if self.network_data:
            findings.extend(self.network_data.get("findings", []))
        if self.domain_data:
            findings.extend(self.domain_data.get("findings", []))
        score = self.ai_engine.risk_score(findings)
        self.risk_label.setText(f"Risk Score: {score}/100")

    def _show_network_message(self, title: str, detail: str) -> None:
        self.network_table.setRowCount(1)
        values = ["", "", "", "", title, detail, "", "", ""]
        for column, value in enumerate(values):
            self.network_table.setItem(0, column, QTableWidgetItem(value))

    def _update_scan_hint(self, _index: int | None = None) -> None:
        profile = self.scan_profile.currentData()
        self.scan_hint.setText(NetworkScanner.profile_description(profile))

    def _ai_status_text(self) -> str:
        if self.ai_engine.has_api_key():
            return "AI Mode: Gemini key configured. Reports will use Gemini when available."
        return "AI Mode: Local fallback. Add a Gemini API key to enable AI reports."

    def _set_busy(self, message: str, busy: bool) -> None:
        self.status_label.setText(message)
        self.progress.setVisible(busy)
        QApplication.processEvents()

    def _cleanup_thread(self, thread: QThread) -> None:
        if thread in self.active_threads:
            self.active_threads.remove(thread)
        worker = getattr(thread, "_skyguard_worker", None)
        if worker in self.active_workers:
            self.active_workers.remove(worker)
        thread.deleteLater()

    def _show_error(self, title: str, message: str) -> None:
        QMessageBox.warning(self, title, message)
        self.status_label.setText("Ready")

    def _apply_theme(self) -> None:
        self.setFont(QFont("Segoe UI", 10))
        self.setStyleSheet(
            """
            QWidget {
                background: #0d1117;
                color: #d8dee9;
                font-family: "Segoe UI", Arial, sans-serif;
            }
            QLabel#Header {
                color: #f8fafc;
                font-size: 28px;
                font-weight: 700;
            }
            QLabel#Subtitle {
                color: #8b949e;
                font-size: 13px;
            }
            QLabel#Status {
                color: #8b949e;
                padding-top: 4px;
            }
            QLabel#ScanHint {
                color: #8b949e;
                font-size: 12px;
            }
            QLabel#RiskLabel {
                color: #7dd3fc;
                font-size: 16px;
                font-weight: 700;
            }
            QLabel#AIStatus {
                color: #8b949e;
                font-size: 12px;
            }
            QGroupBox {
                border: 1px solid #30363d;
                border-radius: 8px;
                margin-top: 14px;
                padding: 18px 12px 12px 12px;
                background: #161b22;
                font-weight: 700;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 12px;
                padding: 0 8px;
                color: #f8fafc;
            }
            QLineEdit, QPlainTextEdit, QTableWidget, QComboBox {
                background: #0b1220;
                border: 1px solid #30363d;
                border-radius: 6px;
                color: #e5e7eb;
                selection-background-color: #2563eb;
            }
            QLineEdit, QComboBox {
                padding: 9px 10px;
            }
            QComboBox::drop-down {
                border: 0;
                width: 24px;
            }
            QPlainTextEdit {
                padding: 10px;
                font-family: Consolas, "Courier New", monospace;
                font-size: 12px;
            }
            QPushButton {
                background: #1f6feb;
                color: white;
                border: 0;
                border-radius: 6px;
                padding: 9px 14px;
                font-weight: 700;
            }
            QPushButton:hover {
                background: #388bfd;
            }
            QPushButton:disabled {
                background: #30363d;
                color: #8b949e;
            }
            QHeaderView::section {
                background: #111827;
                color: #cbd5e1;
                border: 0;
                border-right: 1px solid #30363d;
                padding: 7px;
                font-weight: 700;
            }
            QTableWidget {
                gridline-color: #30363d;
                alternate-background-color: #111827;
            }
            QTableWidget::item {
                padding: 6px;
            }
            QProgressBar {
                background: #0b1220;
                border: 1px solid #30363d;
                border-radius: 5px;
                min-height: 8px;
                max-height: 8px;
                text-align: center;
            }
            QProgressBar::chunk {
                background: #1f6feb;
                border-radius: 5px;
            }
            """
        )
