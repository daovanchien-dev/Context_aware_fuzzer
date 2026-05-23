"""
Phase 8: Response Analyzer

Nhiệm vụ:
- Nhận BaselineProfile từ Phase 5
- Nhận UnifiedResponse từ Phase 3
- So sánh fuzzed response với baseline
- Phát hiện anomaly:
    - SQL syntax error
    - XSS reflection
    - Status code thay đổi bất thường
    - Content-Length lệch mạnh
    - Content-Type thay đổi
    - Time-based delay
    - Network/request error
- Trả về AnalysisResult:
    - is_suspicious
    - anomaly_reasons
    - detected_family
    - evidence

Module này KHÔNG gửi HTTP request.
Module này KHÔNG fuzzing.
Module này KHÔNG escalation.
Module này KHÔNG chấm confidence score.
"""

import logging
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


try:
    from baseline_collector import BaselineProfile
    from http_client import UnifiedResponse
except ImportError:
    from core.baseline_collector import BaselineProfile
    from core.http_client import UnifiedResponse


@dataclass
class AnalysisResult:
    """
    Kết quả phân tích response sau khi fuzz.

    Fields:
        is_suspicious:
            True nếu response có dấu hiệu bất thường.

        anomaly_reasons:
            Danh sách lý do khiến response bị đánh dấu nghi ngờ.

        detected_family:
            Nhóm lỗ hổng nghi ngờ:
                - sqli
                - xss
                - path_traversal
                - command_injection
                - time_based
                - unknown

        evidence:
            Dict chứa bằng chứng kỹ thuật để Phase 10 chấm điểm.
    """

    is_suspicious: bool
    anomaly_reasons: List[str] = field(default_factory=list)
    detected_family: str = "unknown"
    evidence: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """
        Convert AnalysisResult sang dict.
        """
        return {
            "is_suspicious": self.is_suspicious,
            "anomaly_reasons": self.anomaly_reasons,
            "detected_family": self.detected_family,
            "evidence": self.evidence
        }


class ResponseAnalyzer:
    """
    Response Analyzer.

    Contract:
    ---------
    Input:
        - BaselineProfile
        - UnifiedResponse
        - payload optional

    Output:
        - AnalysisResult

    Public methods:
        - analyze()

    Các module khác KHÔNG gọi private method.
    """

    SQL_ERROR_PATTERNS = [
        r"SQL syntax",
        r"mysql_fetch",
        r"mysql_num_rows",
        r"mysql_query",
        r"mysqli_",
        r"MariaDB",
        r"MySQL",
        r"PostgreSQL",
        r"pg_query",
        r"SQLite",
        r"sqlite3",
        r"ORA-\d+",
        r"Oracle error",
        r"ODBC SQL",
        r"JDBC SQL",
        r"SQLSTATE",
        r"syntax error at or near",
        r"unclosed quotation mark",
        r"quoted string not properly terminated",
        r"Microsoft SQL Server",
        r"Incorrect syntax near"
    ]

    PATH_TRAVERSAL_PATTERNS = [
        r"root:x:0:0:",
        r"daemon:x:",
        r"bin:x:",
        r"\[extensions\]",
        r"\[fonts\]",
        r"boot loader",
        r"windows\\system32",
        r"/bin/bash",
        r"/etc/passwd"
    ]

    COMMAND_INJECTION_PATTERNS = [
        r"uid=\d+",
        r"gid=\d+",
        r"groups=\d+",
        r"root",
        r"administrator",
        r"nt authority",
        r"command not found",
        r"not recognized as an internal or external command"
    ]

    SERVER_ERROR_CODES = {500, 501, 502, 503, 504}

    def __init__(
        self,
        length_diff_ratio_threshold: float = 0.30,
        time_delay_threshold_seconds: float = 3.0
    ):
        """
        Khởi tạo ResponseAnalyzer.

        :param length_diff_ratio_threshold:
            Ngưỡng lệch Content-Length.
            0.30 nghĩa là lệch trên 30% so với baseline thì đáng nghi.

        :param time_delay_threshold_seconds:
            Ngưỡng delay tuyệt đối.
            Nếu fuzzed_response chậm hơn baseline từ 3s trở lên thì đáng nghi.
        """
        self.logger = self._setup_logger()
        self.length_diff_ratio_threshold = length_diff_ratio_threshold
        self.time_delay_threshold_seconds = time_delay_threshold_seconds

    def analyze(
        self,
        baseline: BaselineProfile,
        fuzzed_response: UnifiedResponse,
        payload: Optional[str] = None
    ) -> AnalysisResult:
        """
        Public method.

        Phân tích fuzzed_response bằng cách so với baseline.

        :param baseline: BaselineProfile từ Phase 5
        :param fuzzed_response: UnifiedResponse từ HTTPClient
        :param payload: payload đã dùng, nếu có
        :return: AnalysisResult
        """
        reasons: List[str] = []
        evidence: Dict[str, Any] = self._build_base_evidence(
            baseline=baseline,
            fuzzed_response=fuzzed_response,
            payload=payload
        )

        detected_family = "unknown"

        if fuzzed_response.is_error:
            reasons.append(f"Network/request error during fuzzed request: {fuzzed_response.error}")
            evidence["network_error"] = True

            return AnalysisResult(
                is_suspicious=False,
                anomaly_reasons=reasons,
                detected_family="network",
                evidence=evidence
            )

        sql_result = self._detect_sql_error(fuzzed_response.text)

        if sql_result:
            reasons.append(f"SQL error pattern detected: {sql_result}")
            evidence["sql_error_pattern"] = sql_result
            detected_family = "sqli"

        xss_reflected = self._detect_xss_reflection(
            response_text=fuzzed_response.text,
            payload=payload
        )

        if xss_reflected:
            reasons.append("Payload reflection detected in response body")
            evidence["reflected_payload"] = payload

            if detected_family == "unknown":
                detected_family = "xss"

        path_result = self._detect_pattern_family(
            response_text=fuzzed_response.text,
            patterns=self.PATH_TRAVERSAL_PATTERNS
        )

        if path_result:
            reasons.append(f"Path traversal evidence detected: {path_result}")
            evidence["path_traversal_pattern"] = path_result

            if detected_family == "unknown":
                detected_family = "path_traversal"

        command_result = self._detect_pattern_family(
            response_text=fuzzed_response.text,
            patterns=self.COMMAND_INJECTION_PATTERNS
        )

        if command_result:
            reasons.append(f"Command injection evidence detected: {command_result}")
            evidence["command_injection_pattern"] = command_result

            if detected_family == "unknown":
                detected_family = "command_injection"

        if self._has_status_code_anomaly(baseline, fuzzed_response):
            reasons.append(
                f"Response status changed from {baseline.status_code} to {fuzzed_response.status_code}"
            )
            evidence["status_code_changed"] = True

            if fuzzed_response.status_code in self.SERVER_ERROR_CODES and detected_family == "unknown":
                detected_family = "server_error"

        length_anomaly = self._calculate_length_anomaly(baseline, fuzzed_response)

        if length_anomaly["is_anomaly"]:
            reasons.append(
                f"Content-Length changed significantly: "
                f"baseline={length_anomaly['baseline_length']}, "
                f"fuzzed={length_anomaly['fuzzed_length']}, "
                f"diff_ratio={length_anomaly['diff_ratio']:.2f}"
            )
            evidence["length_anomaly"] = length_anomaly

        if self._has_content_type_anomaly(baseline, fuzzed_response):
            reasons.append(
                f"Content-Type changed from '{baseline.content_type}' "
                f"to '{fuzzed_response.headers.get('Content-Type', '')}'"
            )
            evidence["content_type_changed"] = True

        time_anomaly = self._calculate_time_anomaly(baseline, fuzzed_response)

        if time_anomaly["is_anomaly"]:
            reasons.append(
                f"Response time increased significantly: "
                f"baseline_avg={time_anomaly['baseline_time']:.4f}s, "
                f"fuzzed={time_anomaly['fuzzed_time']:.4f}s, "
                f"delta={time_anomaly['delta']:.4f}s"
            )
            evidence["time_anomaly"] = time_anomaly

            if detected_family == "unknown":
                detected_family = "time_based"

        is_suspicious = len(reasons) > 0

        result = AnalysisResult(
            is_suspicious=is_suspicious,
            anomaly_reasons=reasons,
            detected_family=detected_family,
            evidence=evidence
        )

        if result.is_suspicious:
            self.logger.info(
                "Suspicious response detected. Family=%s Reasons=%s",
                result.detected_family,
                result.anomaly_reasons
            )
        else:
            self.logger.info("No suspicious anomaly detected.")

        return result

    def _build_base_evidence(
        self,
        baseline: BaselineProfile,
        fuzzed_response: UnifiedResponse,
        payload: Optional[str]
    ) -> Dict[str, Any]:
        """
        Private method.

        Tạo evidence cơ bản cho mọi kết quả phân tích.
        """
        fuzzed_content_type = ""

        if fuzzed_response.headers:
            fuzzed_content_type = fuzzed_response.headers.get("Content-Type", "")

        return {
            "payload": payload,
            "baseline_status_code": baseline.status_code,
            "fuzzed_status_code": fuzzed_response.status_code,
            "baseline_content_length": baseline.content_length,
            "fuzzed_content_length": len(fuzzed_response.text or ""),
            "baseline_content_type": baseline.content_type,
            "fuzzed_content_type": fuzzed_content_type,
            "baseline_average_response_time": baseline.average_response_time,
            "fuzzed_response_time": fuzzed_response.response_time,
            "url": fuzzed_response.url,
            "method": fuzzed_response.method
        }

    def _detect_sql_error(self, response_text: str) -> Optional[str]:
        """
        Private method.

        Phát hiện SQL error pattern trong response body.
        """
        if not response_text:
            return None

        for pattern in self.SQL_ERROR_PATTERNS:
            if re.search(pattern, response_text, re.IGNORECASE):
                return pattern

        return None

    def _detect_xss_reflection(
        self,
        response_text: str,
        payload: Optional[str]
    ) -> bool:
        """
        Private method.

        Phát hiện payload có bị reflect lại trong response hay không.

        Lưu ý:
        - Reflection chưa đủ kết luận XSS.
        - Nó chỉ là tín hiệu đáng nghi để Phase 9/10 xác minh thêm.
        """
        if not response_text or not payload:
            return False

        if payload in response_text:
            return True

        normalized_payload = payload.strip()

        if normalized_payload and normalized_payload in response_text:
            return True

        return False

    def _detect_pattern_family(
        self,
        response_text: str,
        patterns: List[str]
    ) -> Optional[str]:
        """
        Private method.

        Phát hiện một nhóm pattern bất kỳ.
        """
        if not response_text:
            return None

        for pattern in patterns:
            if re.search(pattern, response_text, re.IGNORECASE):
                return pattern

        return None

    def _has_status_code_anomaly(
        self,
        baseline: BaselineProfile,
        fuzzed_response: UnifiedResponse
    ) -> bool:
        """
        Private method.

        Phát hiện status code thay đổi đáng nghi.
        """
        if fuzzed_response.status_code == baseline.status_code:
            return False

        if fuzzed_response.status_code in self.SERVER_ERROR_CODES:
            return True

        if baseline.status_code < 400 <= fuzzed_response.status_code:
            return True

        if baseline.status_code == 200 and fuzzed_response.status_code in {401, 403}:
            return True

        return False

    def _calculate_length_anomaly(
        self,
        baseline: BaselineProfile,
        fuzzed_response: UnifiedResponse
    ) -> Dict[str, Any]:
        """
        Private method.

        Tính độ lệch Content-Length.
        """
        baseline_length = baseline.content_length
        fuzzed_length = len(fuzzed_response.text or "")

        if baseline_length <= 0:
            diff_ratio = 1.0 if fuzzed_length > 0 else 0.0
        else:
            diff_ratio = abs(fuzzed_length - baseline_length) / baseline_length

        return {
            "baseline_length": baseline_length,
            "fuzzed_length": fuzzed_length,
            "diff_ratio": diff_ratio,
            "threshold": self.length_diff_ratio_threshold,
            "is_anomaly": diff_ratio >= self.length_diff_ratio_threshold
        }

    def _has_content_type_anomaly(
        self,
        baseline: BaselineProfile,
        fuzzed_response: UnifiedResponse
    ) -> bool:
        """
        Private method.

        Phát hiện Content-Type thay đổi.
        """
        baseline_content_type = baseline.content_type or ""
        fuzzed_content_type = ""

        if fuzzed_response.headers:
            fuzzed_content_type = fuzzed_response.headers.get("Content-Type", "")

        if not baseline_content_type or not fuzzed_content_type:
            return False

        baseline_main_type = baseline_content_type.split(";")[0].strip().lower()
        fuzzed_main_type = fuzzed_content_type.split(";")[0].strip().lower()

        return baseline_main_type != fuzzed_main_type

    def _calculate_time_anomaly(
        self,
        baseline: BaselineProfile,
        fuzzed_response: UnifiedResponse
    ) -> Dict[str, Any]:
        """
        Private method.

        Phát hiện time-based delay.
        """
        baseline_time = baseline.average_response_time
        fuzzed_time = fuzzed_response.response_time
        delta = fuzzed_time - baseline_time

        return {
            "baseline_time": baseline_time,
            "fuzzed_time": fuzzed_time,
            "delta": delta,
            "threshold": self.time_delay_threshold_seconds,
            "is_anomaly": delta >= self.time_delay_threshold_seconds
        }

    def _setup_logger(self) -> logging.Logger:
        """
        Private method.

        Tạo logger riêng cho ResponseAnalyzer.
        """
        logger = logging.getLogger("ResponseAnalyzer")

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
    Test nhanh Phase 8.

    Chạy:
        python core/response_analyzer.py

    Test này không cần server localhost.
    Nó tạo baseline giả và fuzzed response giả để kiểm tra logic analyzer.
    """

    baseline = BaselineProfile(
        status_code=200,
        content_length=28,
        average_response_time=0.05,
        content_type="application/json",
        body_hash="dummy_hash",
        sample_count=3,
        url="http://localhost:5000/api/users?id=1",
        method="GET",
        headers={
            "Content-Type": "application/json"
        },
        text_preview='{"id":1,"name":"admin"}'
    )

    fuzzed_response = UnifiedResponse(
        status_code=500,
        response_time=0.08,
        text="SQL syntax error near ' OR '1'='1",
        headers={
            "Content-Type": "text/html"
        },
        url="http://localhost:5000/api/users?id=1'",
        method="GET",
        error=None,
        is_error=False
    )

    analyzer = ResponseAnalyzer()

    result = analyzer.analyze(
        baseline=baseline,
        fuzzed_response=fuzzed_response,
        payload="' OR '1'='1"
    )

    print("\n===== Analysis Result =====")
    for key, value in result.to_dict().items():
        print(f"{key}: {value}")