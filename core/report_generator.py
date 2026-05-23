"""
Phase 11: Report Generator

Nhiệm vụ:
- Nhận danh sách Finding từ Phase 10
- Chỉ đưa finding hợp lệ vào report nếu confidence >= 70
- Sinh reports/report.json
- Sinh reports/report.html
- Mỗi finding có curl command để reproduce

Module này KHÔNG gửi HTTP request.
Module này KHÔNG fuzzing.
Module này KHÔNG phân tích response.
Module này KHÔNG chấm điểm.
"""

import json
import logging
import html
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional


try:
    from confidence_scorer import ConfidenceResult
except ImportError:
    from core.confidence_scorer import ConfidenceResult


@dataclass
class Finding:
    """
    Finding là một phát hiện bảo mật đã được chấm điểm.

    Fields:
        title:
            Tiêu đề finding.

        finding_type:
            Nhóm lỗ hổng, ví dụ: sqli, xss, idor.

        endpoint:
            URL endpoint bị ảnh hưởng.

        method:
            HTTP method.

        parameter:
            Tên tham số bị fuzz.

        location:
            Vị trí tham số: query/json.

        payload:
            Payload gây ra dấu hiệu bất thường.

        confidence:
            ConfidenceResult từ Phase 10.

        evidence:
            Bằng chứng kỹ thuật.

        request_params:
            Query params dùng để reproduce.

        request_json_body:
            JSON body dùng để reproduce.

        headers:
            Headers dùng để reproduce.

        description:
            Mô tả ngắn.

        recommendation:
            Khuyến nghị xử lý.
    """

    title: str
    finding_type: str
    endpoint: str
    method: str
    parameter: str
    location: str
    payload: str
    confidence: ConfidenceResult
    evidence: Dict[str, Any] = field(default_factory=dict)
    request_params: Dict[str, Any] = field(default_factory=dict)
    request_json_body: Dict[str, Any] = field(default_factory=dict)
    headers: Dict[str, Any] = field(default_factory=dict)
    description: str = ""
    recommendation: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """
        Convert Finding sang dict.
        """
        return {
            "title": self.title,
            "finding_type": self.finding_type,
            "endpoint": self.endpoint,
            "method": self.method,
            "parameter": self.parameter,
            "location": self.location,
            "payload": self.payload,
            "confidence": self.confidence.to_dict(),
            "evidence": self.evidence,
            "request": {
                "headers": self.headers,
                "params": self.request_params,
                "json_body": self.request_json_body
            },
            "curl": self.build_curl_command(),
            "description": self.description,
            "recommendation": self.recommendation
        }

    def build_curl_command(self) -> str:
        """
        Sinh curl command để reproduce finding.
        """
        method = self.method.upper()
        url = self.endpoint

        curl_parts = [
            "curl",
            "-i",
            "-X",
            self._shell_quote(method)
        ]

        for key, value in self.headers.items():
            # Không đưa Authorization/Cookie thật vào report để tránh lộ secret.
            if key.lower() in {"authorization", "cookie"}:
                safe_value = "<REDACTED>"
            else:
                safe_value = str(value)

            curl_parts.extend([
                "-H",
                self._shell_quote(f"{key}: {safe_value}")
            ])

        if self.location == "query" and self.request_params:
            query_string = self._build_query_string(self.request_params)
            separator = "&" if "?" in url else "?"
            url = f"{url}{separator}{query_string}"

        if self.location == "json" and self.request_json_body:
            curl_parts.extend([
                "-H",
                self._shell_quote("Content-Type: application/json")
            ])
            curl_parts.extend([
                "-d",
                self._shell_quote(json.dumps(self.request_json_body, ensure_ascii=False))
            ])

        curl_parts.append(self._shell_quote(url))

        return " ".join(curl_parts)

    def _build_query_string(self, params: Dict[str, Any]) -> str:
        """
        Build query string đơn giản, đủ dùng cho report reproduce.
        """
        from urllib.parse import urlencode

        return urlencode(params, doseq=True)

    def _shell_quote(self, value: str) -> str:
        """
        Quote chuỗi cho Windows/Linux shell ở mức cơ bản.
        Dùng double quote và escape double quote bên trong.
        """
        value = str(value).replace('"', '\\"')
        return f'"{value}"'


class ReportGeneratorError(Exception):
    """
    Exception riêng cho ReportGenerator.
    """
    pass


class ReportGenerator:
    """
    Report Generator.

    Contract:
    ---------
    Input:
        - List[Finding]

    Output:
        - reports/report.json
        - reports/report.html

    Public methods:
        - generate()
        - generate_json_report()
        - generate_html_report()

    Các module khác KHÔNG gọi private method.
    """

    def __init__(
        self,
        output_dir: str = "reports",
        json_filename: str = "report.json",
        html_filename: str = "report.html"
    ):
        """
        Khởi tạo ReportGenerator.

        :param output_dir: thư mục output report
        :param json_filename: tên file JSON report
        :param html_filename: tên file HTML report
        """
        self.logger = self._setup_logger()

        self.output_dir = Path(output_dir)
        self.json_path = self.output_dir / json_filename
        self.html_path = self.output_dir / html_filename

        self.output_dir.mkdir(parents=True, exist_ok=True)

    def generate(self, findings: List[Finding]) -> Dict[str, str]:
        """
        Public method.

        Sinh cả JSON report và HTML report.

        :param findings: danh sách Finding
        :return: dict chứa đường dẫn report
        """
        valid_findings = self._filter_valid_findings(findings)

        report_data = self._build_report_data(valid_findings)

        self.generate_json_report(report_data)
        self.generate_html_report(report_data)

        self.logger.info(
            "Report generated successfully. json=%s html=%s valid_findings=%s",
            self.json_path,
            self.html_path,
            len(valid_findings)
        )

        return {
            "json_report": str(self.json_path),
            "html_report": str(self.html_path)
        }

    def generate_json_report(self, report_data: Dict[str, Any]) -> None:
        """
        Public method.

        Ghi report JSON.
        """
        try:
            with self.json_path.open("w", encoding="utf-8") as file:
                json.dump(report_data, file, indent=4, ensure_ascii=False)

        except OSError as error:
            raise ReportGeneratorError(f"Cannot write JSON report: {error}") from error

    def generate_html_report(self, report_data: Dict[str, Any]) -> None:
        """
        Public method.

        Ghi report HTML.
        """
        try:
            html_content = self._render_html(report_data)

            with self.html_path.open("w", encoding="utf-8") as file:
                file.write(html_content)

        except OSError as error:
            raise ReportGeneratorError(f"Cannot write HTML report: {error}") from error

    def _filter_valid_findings(self, findings: List[Finding]) -> List[Finding]:
        """
        Private method.

        Chỉ giữ finding có confidence hợp lệ.
        """
        if not isinstance(findings, list):
            self.logger.warning("findings must be a list. Got: %s", type(findings).__name__)
            return []

        valid_findings: List[Finding] = []

        for finding in findings:
            if not isinstance(finding, Finding):
                self.logger.warning("Skipping invalid finding object: %s", type(finding).__name__)
                continue

            if finding.confidence and finding.confidence.is_valid_finding:
                valid_findings.append(finding)
            else:
                self.logger.info("Skipping non-valid finding: %s", finding.title)

        return valid_findings

    def _build_report_data(self, findings: List[Finding]) -> Dict[str, Any]:
        """
        Private method.

        Tạo cấu trúc report chuẩn.
        """
        finding_dicts = [
            finding.to_dict()
            for finding in findings
        ]

        severity_summary = self._build_severity_summary(findings)

        return {
            "tool": "Context-Aware & Feedback-Driven Web Fuzzer",
            "generated_at": datetime.now().isoformat(timespec="seconds"),
            "summary": {
                "total_valid_findings": len(findings),
                "severity": severity_summary
            },
            "findings": finding_dicts
        }

    def _build_severity_summary(self, findings: List[Finding]) -> Dict[str, int]:
        """
        Private method.

        Đếm số lượng finding theo severity.
        """
        summary = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "informational": 0
        }

        for finding in findings:
            severity = finding.confidence.severity

            if severity not in summary:
                summary[severity] = 0

            summary[severity] += 1

        return summary

    def _render_html(self, report_data: Dict[str, Any]) -> str:
        """
        Private method.

        Render HTML report.
        Dùng html.escape để tránh HTML injection trong report.
        """
        findings_html = ""

        findings = report_data.get("findings", [])

        if not findings:
            findings_html = """
            <div class="empty">
                No valid findings were found.
            </div>
            """
        else:
            for index, finding in enumerate(findings, start=1):
                findings_html += self._render_finding_card(index, finding)

        summary = report_data.get("summary", {})
        severity = summary.get("severity", {})

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Context-Aware Fuzzer Report</title>
    <style>
        body {{
            font-family: Arial, sans-serif;
            background: #f5f7fb;
            color: #222;
            margin: 0;
            padding: 24px;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
        }}
        .header {{
            background: #111827;
            color: white;
            padding: 24px;
            border-radius: 12px;
            margin-bottom: 20px;
        }}
        .header h1 {{
            margin: 0 0 8px 0;
        }}
        .summary {{
            display: grid;
            grid-template-columns: repeat(5, 1fr);
            gap: 12px;
            margin-bottom: 20px;
        }}
        .box {{
            background: white;
            border-radius: 10px;
            padding: 16px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.06);
        }}
        .finding {{
            background: white;
            border-radius: 12px;
            padding: 20px;
            margin-bottom: 18px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.06);
            border-left: 6px solid #374151;
        }}
        .severity-critical {{ border-left-color: #7f1d1d; }}
        .severity-high {{ border-left-color: #dc2626; }}
        .severity-medium {{ border-left-color: #f59e0b; }}
        .severity-low {{ border-left-color: #2563eb; }}
        .severity-informational {{ border-left-color: #6b7280; }}
        .meta {{
            display: grid;
            grid-template-columns: 180px 1fr;
            gap: 8px;
            margin: 12px 0;
        }}
        .label {{
            font-weight: bold;
            color: #374151;
        }}
        pre {{
            background: #0f172a;
            color: #e5e7eb;
            padding: 14px;
            border-radius: 8px;
            overflow-x: auto;
            white-space: pre-wrap;
            word-break: break-word;
        }}
        code {{
            background: #eef2ff;
            padding: 2px 5px;
            border-radius: 4px;
        }}
        .empty {{
            background: white;
            border-radius: 12px;
            padding: 24px;
            text-align: center;
            color: #6b7280;
        }}
    </style>
</head>
<body>
<div class="container">
    <div class="header">
        <h1>Context-Aware & Feedback-Driven Web Fuzzer Report</h1>
        <div>Generated at: {html.escape(str(report_data.get("generated_at", "")))}</div>
        <div>Total valid findings: {html.escape(str(summary.get("total_valid_findings", 0)))}</div>
    </div>

    <div class="summary">
        <div class="box"><b>Critical</b><br>{severity.get("critical", 0)}</div>
        <div class="box"><b>High</b><br>{severity.get("high", 0)}</div>
        <div class="box"><b>Medium</b><br>{severity.get("medium", 0)}</div>
        <div class="box"><b>Low</b><br>{severity.get("low", 0)}</div>
        <div class="box"><b>Info</b><br>{severity.get("informational", 0)}</div>
    </div>

    {findings_html}
</div>
</body>
</html>
"""

    def _render_finding_card(self, index: int, finding: Dict[str, Any]) -> str:
        """
        Private method.

        Render một finding thành HTML card.
        """
        confidence = finding.get("confidence", {})
        severity = confidence.get("severity", "informational")
        score = confidence.get("score", 0)
        reasons = confidence.get("reasons", [])

        reasons_html = "".join(
            f"<li>{html.escape(str(reason))}</li>"
            for reason in reasons
        )

        evidence_json = json.dumps(
            finding.get("evidence", {}),
            indent=4,
            ensure_ascii=False
        )

        return f"""
    <div class="finding severity-{html.escape(str(severity))}">
        <h2>#{index} {html.escape(str(finding.get("title", "")))}</h2>

        <div class="meta">
            <div class="label">Type</div>
            <div>{html.escape(str(finding.get("finding_type", "")))}</div>

            <div class="label">Severity</div>
            <div>{html.escape(str(severity))}</div>

            <div class="label">Confidence Score</div>
            <div>{html.escape(str(score))}/100</div>

            <div class="label">Endpoint</div>
            <div><code>{html.escape(str(finding.get("endpoint", "")))}</code></div>

            <div class="label">Method</div>
            <div>{html.escape(str(finding.get("method", "")))}</div>

            <div class="label">Parameter</div>
            <div>{html.escape(str(finding.get("parameter", "")))}</div>

            <div class="label">Location</div>
            <div>{html.escape(str(finding.get("location", "")))}</div>

            <div class="label">Payload</div>
            <div><code>{html.escape(str(finding.get("payload", "")))}</code></div>
        </div>

        <h3>Description</h3>
        <p>{html.escape(str(finding.get("description", "")))}</p>

        <h3>Reasons</h3>
        <ul>{reasons_html}</ul>

        <h3>Reproduce with curl</h3>
        <pre>{html.escape(str(finding.get("curl", "")))}</pre>

        <h3>Recommendation</h3>
        <p>{html.escape(str(finding.get("recommendation", "")))}</p>

        <h3>Evidence</h3>
        <pre>{html.escape(evidence_json)}</pre>
    </div>
"""

    def _setup_logger(self) -> logging.Logger:
        """
        Private method.

        Tạo logger riêng cho ReportGenerator.
        """
        logger = logging.getLogger("ReportGenerator")

        if not logger.handlers:
            logger.setLevel(logging.INFO)

            formatter = logging.Formatter(
                "[%(asctime)s] [%(levelname)s] [%(name)s] %(message)s",
                datefmt="%Y-%m-%d %H:%M:%S"
            )

            console_handler = logging.StreamHandler()
            console_handler.setFormatter(formatter)

            logger.addHandler(console_handler)

        return logger


if __name__ == "__main__":
    """
    Test nhanh Phase 11.

    Chạy:
        python core/report_generator.py

    Test này không cần server localhost.
    Nó tạo một finding giả hợp lệ để sinh report JSON/HTML.
    """

    fake_confidence = ConfidenceResult(
        score=92,
        severity="critical",
        is_valid_finding=True,
        finding_type="sqli",
        reasons=[
            "SQL error pattern detected",
            "Escalation confirmed the suspicious behavior",
            "Escalation family matches initial finding type"
        ],
        evidence={
            "analysis": {
                "sql_error_pattern": "SQL syntax",
                "status_code_changed": True
            },
            "escalation": {
                "confirmed": True
            }
        }
    )

    fake_finding = Finding(
        title="Potential SQL Injection detected on parameter id",
        finding_type="sqli",
        endpoint="http://localhost:5000/api/users",
        method="GET",
        parameter="id",
        location="query",
        payload="1 OR SLEEP(5)",
        confidence=fake_confidence,
        evidence={
            "sql_error_pattern": "SQL syntax",
            "baseline_status_code": 200,
            "fuzzed_status_code": 500
        },
        request_params={
            "id": "1 OR SLEEP(5)"
        },
        request_json_body={},
        headers={
            "Accept": "application/json"
        },
        description=(
            "The target endpoint produced SQL-related error evidence "
            "after the id parameter was modified."
        ),
        recommendation=(
            "Use parameterized queries/prepared statements, validate numeric identifiers, "
            "and avoid returning raw database error messages to clients."
        )
    )

    generator = ReportGenerator()

    output = generator.generate([
        fake_finding
    ])

    print("\n===== Report Generated =====")
    print("JSON:", output["json_report"])
    print("HTML:", output["html_report"])