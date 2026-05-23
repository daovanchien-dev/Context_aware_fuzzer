"""
Phase 10: Confidence Scorer

Nhiệm vụ:
- Nhận AnalysisResult từ Phase 8
- Nhận EscalationResult từ Phase 9 nếu có
- Chấm điểm confidence từ 0 đến 100
- Từ 70 điểm trở lên mới tính là Finding hợp lệ
- Phân loại severity:
    - informational
    - low
    - medium
    - high
    - critical

Module này KHÔNG gửi HTTP request.
Module này KHÔNG fuzzing.
Module này KHÔNG escalation.
Module này KHÔNG sinh report.
"""

import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


try:
    from response_analyzer import AnalysisResult
    from escalation_engine import EscalationResult
except ImportError:
    from core.response_analyzer import AnalysisResult
    from core.escalation_engine import EscalationResult


@dataclass
class ConfidenceResult:
    """
    Kết quả chấm điểm confidence.

    Fields:
        score:
            Điểm từ 0 đến 100.

        severity:
            Mức độ:
                - informational
                - low
                - medium
                - high
                - critical

        is_valid_finding:
            True nếu score >= threshold.

        finding_type:
            Nhóm lỗ hổng nghi ngờ:
                - sqli
                - xss
                - path_traversal
                - command_injection
                - time_based
                - idor
                - server_error
                - unknown

        reasons:
            Lý do cộng/trừ điểm.

        evidence:
            Bằng chứng kỹ thuật phục vụ Phase 11 Report Generator.
    """

    score: int
    severity: str
    is_valid_finding: bool
    finding_type: str
    reasons: List[str] = field(default_factory=list)
    evidence: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """
        Convert ConfidenceResult sang dict.
        """
        return {
            "score": self.score,
            "severity": self.severity,
            "is_valid_finding": self.is_valid_finding,
            "finding_type": self.finding_type,
            "reasons": self.reasons,
            "evidence": self.evidence
        }


class ConfidenceScorer:
    """
    Confidence Scorer.

    Contract:
    ---------
    Input:
        - AnalysisResult từ Phase 8
        - EscalationResult từ Phase 9, optional

    Output:
        - ConfidenceResult

    Public methods:
        - score()

    Các module khác KHÔNG gọi private method.
    """

    DEFAULT_VALID_FINDING_THRESHOLD = 70

    def __init__(self, valid_finding_threshold: int = DEFAULT_VALID_FINDING_THRESHOLD):
        """
        Khởi tạo ConfidenceScorer.

        :param valid_finding_threshold:
            Ngưỡng để coi là finding hợp lệ.
            Mặc định 70.
        """
        self.logger = self._setup_logger()

        if not isinstance(valid_finding_threshold, int):
            valid_finding_threshold = self.DEFAULT_VALID_FINDING_THRESHOLD

        if valid_finding_threshold < 0 or valid_finding_threshold > 100:
            valid_finding_threshold = self.DEFAULT_VALID_FINDING_THRESHOLD

        self.valid_finding_threshold = valid_finding_threshold

    def score(
        self,
        analysis_result: AnalysisResult,
        escalation_result: Optional[EscalationResult] = None
    ) -> ConfidenceResult:
        """
        Public method.

        Chấm điểm dựa trên evidence từ AnalysisResult và EscalationResult.

        :param analysis_result: kết quả phân tích từ Phase 8
        :param escalation_result: kết quả escalation từ Phase 9, nếu có
        :return: ConfidenceResult
        """
        if analysis_result is None:
            return self._build_result(
                score=0,
                finding_type="unknown",
                reasons=["Missing analysis result"],
                evidence={}
            )

        finding_type = analysis_result.detected_family or "unknown"

        score = 0
        reasons: List[str] = []
        evidence: Dict[str, Any] = {
            "analysis": analysis_result.to_dict()
        }

        if not analysis_result.is_suspicious:
            reasons.append("Analysis result is not suspicious")
            return self._build_result(
                score=0,
                finding_type=finding_type,
                reasons=reasons,
                evidence=evidence
            )

        score += 10
        reasons.append("Initial analysis marked response as suspicious")

        score_delta, delta_reasons = self._score_analysis_evidence(analysis_result)
        score += score_delta
        reasons.extend(delta_reasons)

        if escalation_result is not None:
            evidence["escalation"] = escalation_result.to_dict()

            escalation_delta, escalation_reasons = self._score_escalation_evidence(
                escalation_result=escalation_result,
                finding_type=finding_type
            )

            score += escalation_delta
            reasons.extend(escalation_reasons)

        score = self._clamp_score(score)

        result = self._build_result(
            score=score,
            finding_type=finding_type,
            reasons=self._deduplicate_reasons(reasons),
            evidence=evidence
        )

        self.logger.info(
            "Confidence scored. type=%s score=%s severity=%s valid=%s",
            result.finding_type,
            result.score,
            result.severity,
            result.is_valid_finding
        )

        return result

    def _score_analysis_evidence(
        self,
        analysis_result: AnalysisResult
    ) -> tuple[int, List[str]]:
        """
        Private method.

        Chấm điểm dựa trên evidence của Phase 8.
        """
        score = 0
        reasons: List[str] = []

        evidence = analysis_result.evidence or {}
        finding_type = analysis_result.detected_family or "unknown"

        if evidence.get("network_error"):
            score -= 20
            reasons.append("Network error detected; not reliable as vulnerability evidence")
            return score, reasons

        if evidence.get("sql_error_pattern"):
            score += 70
            reasons.append("SQL error pattern detected")

        if evidence.get("reflected_payload"):
            score += 45
            reasons.append("Payload was reflected in response body")

        if evidence.get("path_traversal_pattern"):
            score += 75
            reasons.append("Path traversal evidence pattern detected")

        if evidence.get("command_injection_pattern"):
            score += 75
            reasons.append("Command injection evidence pattern detected")

        if evidence.get("time_anomaly", {}).get("is_anomaly"):
            score += 55
            reasons.append("Time-based delay anomaly detected")

        if evidence.get("status_code_changed"):
            if finding_type == "server_error":
                score += 30
                reasons.append("Server error status code appeared after payload")
            else:
                score += 20
                reasons.append("HTTP status code changed after payload")

        length_anomaly = evidence.get("length_anomaly")

        if isinstance(length_anomaly, dict) and length_anomaly.get("is_anomaly"):
            score += 15
            reasons.append("Content length changed significantly")

        if evidence.get("content_type_changed"):
            score += 10
            reasons.append("Content-Type changed after payload")

        # Family-specific adjustment
        if finding_type == "sqli" and evidence.get("sql_error_pattern"):
            score += 5
            reasons.append("Finding type and SQL evidence are consistent")

        if finding_type == "xss" and evidence.get("reflected_payload"):
            score += 5
            reasons.append("Finding type and reflection evidence are consistent")

        if finding_type == "time_based" and evidence.get("time_anomaly", {}).get("is_anomaly"):
            score += 10
            reasons.append("Finding type and time-based evidence are consistent")

        return score, reasons

    def _score_escalation_evidence(
        self,
        escalation_result: EscalationResult,
        finding_type: str
    ) -> tuple[int, List[str]]:
        """
        Private method.

        Chấm điểm dựa trên kết quả Phase 9.
        """
        score = 0
        reasons: List[str] = []

        if not escalation_result.escalated:
            score -= 5
            reasons.append("Escalation was not performed")
            return score, reasons

        score += 10
        reasons.append("Escalation was performed with deep payloads")

        if escalation_result.tested_payloads:
            score += min(len(escalation_result.tested_payloads) * 3, 10)
            reasons.append("Deep payloads were tested")

        if escalation_result.confirmed:
            score += 35
            reasons.append("Escalation confirmed the suspicious behavior")

            if escalation_result.vulnerability_family == finding_type:
                score += 10
                reasons.append("Escalation family matches initial finding type")

        else:
            score -= 10
            reasons.append("Escalation did not confirm stronger evidence")

        best_analysis = escalation_result.best_analysis

        if best_analysis:
            best_evidence = best_analysis.evidence or {}

            if best_evidence.get("network_error"):
                score -= 15
                reasons.append("Best escalation evidence was only a network error")

            if best_evidence.get("sql_error_pattern"):
                score += 25
                reasons.append("Escalation response contained SQL error evidence")

            if best_evidence.get("reflected_payload"):
                score += 20
                reasons.append("Escalation response reflected deep payload")

            if best_evidence.get("time_anomaly", {}).get("is_anomaly"):
                score += 30
                reasons.append("Escalation response confirmed time delay anomaly")

            if best_evidence.get("path_traversal_pattern"):
                score += 25
                reasons.append("Escalation response contained path traversal evidence")

            if best_evidence.get("command_injection_pattern"):
                score += 25
                reasons.append("Escalation response contained command injection evidence")

        return score, reasons

    def _build_result(
        self,
        score: int,
        finding_type: str,
        reasons: List[str],
        evidence: Dict[str, Any]
    ) -> ConfidenceResult:
        """
        Private method.

        Tạo ConfidenceResult chuẩn.
        """
        score = self._clamp_score(score)
        severity = self._severity_from_score(score)

        return ConfidenceResult(
            score=score,
            severity=severity,
            is_valid_finding=score >= self.valid_finding_threshold,
            finding_type=finding_type,
            reasons=self._deduplicate_reasons(reasons),
            evidence=evidence
        )

    def _severity_from_score(self, score: int) -> str:
        """
        Private method.

        Quy đổi score thành severity.
        """
        if score >= 90:
            return "critical"

        if score >= 75:
            return "high"

        if score >= 50:
            return "medium"

        if score >= 20:
            return "low"

        return "informational"

    def _clamp_score(self, score: int) -> int:
        """
        Private method.

        Ép điểm vào khoảng 0-100.
        """
        if score < 0:
            return 0

        if score > 100:
            return 100

        return int(score)

    def _deduplicate_reasons(self, reasons: List[str]) -> List[str]:
        """
        Private method.

        Loại bỏ reason trùng, giữ nguyên thứ tự.
        """
        unique_reasons: List[str] = []

        for reason in reasons:
            if reason not in unique_reasons:
                unique_reasons.append(reason)

        return unique_reasons

    def _setup_logger(self) -> logging.Logger:
        """
        Private method.

        Tạo logger riêng cho ConfidenceScorer.
        """
        logger = logging.getLogger("ConfidenceScorer")

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
    Test nhanh Phase 10.

    Chạy:
        python core/confidence_scorer.py

    Test này không cần server localhost.
    """

    fake_analysis = AnalysisResult(
        is_suspicious=True,
        anomaly_reasons=[
            "SQL error pattern detected: SQL syntax",
            "Response status changed from 200 to 500"
        ],
        detected_family="sqli",
        evidence={
            "payload": "'",
            "sql_error_pattern": "SQL syntax",
            "status_code_changed": True,
            "baseline_status_code": 200,
            "fuzzed_status_code": 500,
            "baseline_content_length": 28,
            "fuzzed_content_length": 120,
            "baseline_content_type": "application/json",
            "fuzzed_content_type": "text/html",
            "content_type_changed": True
        }
    )

    fake_escalation = EscalationResult(
        escalated=True,
        confirmed=True,
        vulnerability_family="sqli",
        tested_payloads=[
            "' OR SLEEP(5) --",
            "\" OR SLEEP(5) --"
        ],
        confirmation_reasons=[
            "Escalation response contained SQL error evidence"
        ],
        attempts=[],
        best_analysis=fake_analysis
    )

    scorer = ConfidenceScorer()

    result = scorer.score(
        analysis_result=fake_analysis,
        escalation_result=fake_escalation
    )

    print("\n===== Confidence Result =====")
    for key, value in result.to_dict().items():
        print(f"{key}: {value}")