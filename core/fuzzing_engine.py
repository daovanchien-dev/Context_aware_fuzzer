"""
Phase 12: Fuzzing Engine / Integration

Nhiệm vụ:
- Orchestrate toàn bộ workflow từ Phase 2 đến Phase 11
- Load config
- Login nếu auth_enabled = true
- Collect baseline
- Classify parameters
- Generate light payloads
- Send fuzzed requests
- Analyze responses
- Escalate suspicious responses
- Score confidence
- Generate report.json và report.html

"""

import copy
import logging
import threading
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


try:
    from config_manager import ConfigManager
    from http_client import HTTPClient, UnifiedResponse
    from auth_manager import AuthManager
    from baseline_collector import BaselineCollector, BaselineCollectionError, BaselineProfile
    from parameter_classifier import ParameterClassifier, InjectionPoint
    from payload_generator import PayloadGenerator, PayloadItem
    from response_analyzer import ResponseAnalyzer, AnalysisResult
    from escalation_engine import EscalationEngine, EscalationResult
    from confidence_scorer import ConfidenceScorer, ConfidenceResult
    from report_generator import ReportGenerator, Finding
except ImportError:
    from core.config_manager import ConfigManager
    from core.http_client import HTTPClient, UnifiedResponse
    from core.auth_manager import AuthManager
    from core.baseline_collector import BaselineCollector, BaselineCollectionError, BaselineProfile
    from core.parameter_classifier import ParameterClassifier, InjectionPoint
    from core.payload_generator import PayloadGenerator, PayloadItem
    from core.response_analyzer import ResponseAnalyzer, AnalysisResult
    from core.escalation_engine import EscalationEngine, EscalationResult
    from core.confidence_scorer import ConfidenceScorer, ConfidenceResult
    from core.report_generator import ReportGenerator, Finding


@dataclass
class FuzzingSummary:
    """
    Tổng kết một lần chạy fuzzer.

    Fields:
        started:
            Engine đã bắt đầu chạy hay chưa.

        completed:
            Engine đã hoàn tất hay chưa.

        baseline_collected:
            Đã lấy baseline thành công chưa.

        injection_points_count:
            Số InjectionPoint tìm được.

        fuzzed_requests_count:
            Số request fuzz đã gửi.

        suspicious_count:
            Số response bị đánh dấu suspicious.

        valid_findings_count:
            Số finding hợp lệ sau ConfidenceScorer.

        report_paths:
            Đường dẫn report.json và report.html.

        errors:
            Danh sách lỗi có kiểm soát.
    """

    started: bool = False
    completed: bool = False
    baseline_collected: bool = False
    injection_points_count: int = 0
    fuzzed_requests_count: int = 0
    suspicious_count: int = 0
    valid_findings_count: int = 0
    report_paths: Dict[str, str] = field(default_factory=dict)
    errors: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "started": self.started,
            "completed": self.completed,
            "baseline_collected": self.baseline_collected,
            "injection_points_count": self.injection_points_count,
            "fuzzed_requests_count": self.fuzzed_requests_count,
            "suspicious_count": self.suspicious_count,
            "valid_findings_count": self.valid_findings_count,
            "report_paths": self.report_paths,
            "errors": self.errors
        }


@dataclass
class FuzzTaskResult:
    """
    Kết quả xử lý một payload trên một InjectionPoint.
    """

    injection_point: InjectionPoint
    payload_item: PayloadItem
    response: UnifiedResponse
    analysis: AnalysisResult
    escalation: Optional[EscalationResult]
    confidence: ConfidenceResult
    finding: Optional[Finding]
    request_params: Dict[str, Any]
    request_json_body: Dict[str, Any]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "injection_point": self.injection_point.to_dict(),
            "payload_item": self.payload_item.to_dict(),
            "response": self.response.to_dict(),
            "analysis": self.analysis.to_dict(),
            "escalation": self.escalation.to_dict() if self.escalation else None,
            "confidence": self.confidence.to_dict(),
            "finding": self.finding.to_dict() if self.finding else None,
            "request_params": self.request_params,
            "request_json_body": self.request_json_body
        }


class FuzzingEngine:
    """
    Fuzzing Engine.

    Contract:
    Input:
        - config/target.json
        - config/auth_config.json
        - payloads/*.json

    Output:
        - FuzzingSummary
        - reports/report.json
        - reports/report.html

    Public methods:
        - run()

    """

    def __init__(
        self,
        max_payloads_per_point: int = 5,
        max_deep_payloads: int = 3,
        max_workers: int = 1
    ):
        """
        Khởi tạo FuzzingEngine.

        """
        self.logger = self._setup_logger()

        self.max_payloads_per_point = self._normalize_positive_int(
            value=max_payloads_per_point,
            default=5
        )

        self.max_deep_payloads = self._normalize_positive_int(
            value=max_deep_payloads,
            default=3
        )

        self.max_workers = self._normalize_positive_int(
            value=max_workers,
            default=1
        )

        self.findings_lock = threading.Lock()
        self.counter_lock = threading.Lock()

        self.config = ConfigManager()

        self.http_client = HTTPClient(
            default_headers=self.config.get("headers", {}),
            timeout=self.config.get("timeout", 10),
            verify_ssl=self.config.get("verify_ssl", False)
        )

        self.auth_manager = AuthManager(
            config=self.config,
            http_client=self.http_client
        )

        self.baseline_collector = BaselineCollector(
            config=self.config,
            http_client=self.http_client,
            auth_manager=self.auth_manager,
            sample_count=3
        )

        self.parameter_classifier = ParameterClassifier()
        self.payload_generator = PayloadGenerator()
        self.response_analyzer = ResponseAnalyzer()

        self.escalation_engine = EscalationEngine(
            config=self.config,
            http_client=self.http_client,
            auth_manager=self.auth_manager,
            payload_generator=self.payload_generator,
            response_analyzer=self.response_analyzer,
            max_deep_payloads=self.max_deep_payloads
        )

        self.confidence_scorer = ConfidenceScorer()
        self.report_generator = ReportGenerator()

        self.fuzzed_requests_count = 0
        self.suspicious_count = 0

    def run(self) -> FuzzingSummary:
        """
        Public method.

        Chạy toàn bộ workflow fuzzer.

        """
        summary = FuzzingSummary(started=True)

        self.logger.info("Context-Aware Fuzzing Engine started.")

        findings: List[Finding] = []

        try:
            baseline = self.baseline_collector.collect()
            summary.baseline_collected = True

        except BaselineCollectionError as error:
            message = f"Baseline collection failed: {error}"
            self.logger.error(message)
            summary.errors.append(message)

            summary.report_paths = self.report_generator.generate([])
            summary.completed = True

            return summary

        except Exception as error:
            message = f"Unexpected error during baseline collection: {error}"
            self.logger.exception(message)
            summary.errors.append(message)

            summary.report_paths = self.report_generator.generate([])
            summary.completed = True

            return summary

        injection_points = self.parameter_classifier.classify(
            params=self.config.get("params", {}),
            json_body=self.config.get("json_body", {})
        )

        summary.injection_points_count = len(injection_points)

        if not injection_points:
            self.logger.warning("No injection points found. Generating empty report.")
            summary.report_paths = self.report_generator.generate([])
            summary.completed = True
            return summary

        self.logger.info("Injection points discovered: %s", len(injection_points))

        task_results: List[FuzzTaskResult] = []

        # Chạy tuần tự mặc định để tránh race condition với session/auth state.
        # Sau khi có Demo Lab ổn định, có thể nâng cấp sang ThreadPoolExecutor có lock.
        for injection_point in injection_points:
            payload_items = self.payload_generator.get_payloads_for_injection_point(
                injection_point
            )

            payload_items = payload_items[:self.max_payloads_per_point]

            if not payload_items:
                self.logger.info(
                    "No payloads found for injection point: %s",
                    injection_point.path
                )
                continue

            for payload_item in payload_items:
                result = self._process_payload(
                    baseline=baseline,
                    injection_point=injection_point,
                    payload_item=payload_item
                )

                task_results.append(result)

                with self.counter_lock:
                    self.fuzzed_requests_count += 1

                    if result.analysis.is_suspicious:
                        self.suspicious_count += 1

                if result.finding:
                    with self.findings_lock:
                        findings.append(result.finding)

        summary.fuzzed_requests_count = self.fuzzed_requests_count
        summary.suspicious_count = self.suspicious_count
        summary.valid_findings_count = len(findings)

        summary.report_paths = self.report_generator.generate(findings)
        summary.completed = True

        self.logger.info(
            "Fuzzing completed. requests=%s suspicious=%s valid_findings=%s",
            summary.fuzzed_requests_count,
            summary.suspicious_count,
            summary.valid_findings_count
        )

        return summary

    def _process_payload(
        self,
        baseline: BaselineProfile,
        injection_point: InjectionPoint,
        payload_item: PayloadItem
    ) -> FuzzTaskResult:
        """
        Private method.

        Xử lý một payload trên một InjectionPoint:
        - mutate request
        - gửi request
        - analyze
        - escalate nếu suspicious
        - score
        - tạo Finding nếu hợp lệ
        """
        request_params, request_json_body = self._build_mutated_request_data(
            injection_point=injection_point,
            payload=payload_item.payload
        )

        response = self._send_fuzz_request(
            params=request_params,
            json_body=request_json_body
        )

        analysis = self.response_analyzer.analyze(
            baseline=baseline,
            fuzzed_response=response,
            payload=payload_item.payload
        )

        escalation: Optional[EscalationResult] = None

        if analysis.is_suspicious:
            escalation = self.escalation_engine.escalate(
                baseline=baseline,
                injection_point=injection_point,
                initial_analysis=analysis
            )

        confidence = self.confidence_scorer.score(
            analysis_result=analysis,
            escalation_result=escalation
        )

        finding = None

        if confidence.is_valid_finding:
            finding = self._build_finding(
                injection_point=injection_point,
                payload_item=payload_item,
                confidence=confidence,
                request_params=request_params,
                request_json_body=request_json_body,
                analysis=analysis,
                escalation=escalation
            )

        return FuzzTaskResult(
            injection_point=injection_point,
            payload_item=payload_item,
            response=response,
            analysis=analysis,
            escalation=escalation,
            confidence=confidence,
            finding=finding,
            request_params=request_params,
            request_json_body=request_json_body
        )

    def _build_mutated_request_data(
        self,
        injection_point: InjectionPoint,
        payload: str
    ) -> tuple[Dict[str, Any], Dict[str, Any]]:
        """
        Private method.

        Tạo params/json_body mới bằng cách thay đúng tham số cần fuzz.
        """
        original_params = copy.deepcopy(self.config.get("params", {}))
        original_json_body = copy.deepcopy(self.config.get("json_body", {}))

        if not isinstance(original_params, dict):
            original_params = {}

        if not isinstance(original_json_body, dict):
            original_json_body = {}

        if injection_point.location == "query":
            original_params[injection_point.name] = payload
            return original_params, original_json_body

        if injection_point.location == "json":
            if injection_point.path and injection_point.path.startswith("json."):
                path_parts = injection_point.path.replace("json.", "", 1).split(".")
                self._set_nested_value(
                    data=original_json_body,
                    path_parts=path_parts,
                    value=payload
                )
            else:
                original_json_body[injection_point.name] = payload

            return original_params, original_json_body

        self.logger.warning(
            "Unknown injection point location: %s",
            injection_point.location
        )

        return original_params, original_json_body

    def _set_nested_value(
        self,
        data: Dict[str, Any],
        path_parts: List[str],
        value: Any
    ) -> None:
        """
        Private method.

        Set nested JSON value.
        """
        if not path_parts:
            return

        current = data

        for part in path_parts[:-1]:
            if part not in current or not isinstance(current[part], dict):
                current[part] = {}

            current = current[part]

        current[path_parts[-1]] = value

    def _send_fuzz_request(
        self,
        params: Dict[str, Any],
        json_body: Dict[str, Any]
    ) -> UnifiedResponse:
        """
        Private method.

        Gửi request fuzz.
        Nếu gặp 401/403 thì refresh auth một lần và gửi lại.
        """
        method = self.config.get("method", "GET")
        url = self.config.get("target_url")
        headers = self.config.get("headers", {})
        timeout = self.config.get("timeout", 10)
        verify_ssl = self.config.get("verify_ssl", False)

        headers = self.auth_manager.attach_auth(headers)

        response = self.http_client.request(
            method=method,
            url=url,
            headers=headers,
            params=params,
            json_body=json_body,
            timeout=timeout,
            verify_ssl=verify_ssl
        )

        if self.auth_manager.is_auth_error(response):
            self.logger.warning(
                "Fuzz request returned auth error HTTP %s. Trying refresh_auth() once.",
                response.status_code
            )

            refresh_success = self.auth_manager.refresh_auth()

            if not refresh_success:
                self.logger.error("refresh_auth() failed during fuzz request.")
                return response

            refreshed_headers = self.auth_manager.attach_auth(
                self.config.get("headers", {})
            )

            response = self.http_client.request(
                method=method,
                url=url,
                headers=refreshed_headers,
                params=params,
                json_body=json_body,
                timeout=timeout,
                verify_ssl=verify_ssl
            )

        return response

    def _build_finding(
        self,
        injection_point: InjectionPoint,
        payload_item: PayloadItem,
        confidence: ConfidenceResult,
        request_params: Dict[str, Any],
        request_json_body: Dict[str, Any],
        analysis: AnalysisResult,
        escalation: Optional[EscalationResult]
    ) -> Finding:
        """
        Private method.

        Tạo Finding cho Phase 11.
        """
        finding_type = confidence.finding_type

        title = (
            f"Potential {finding_type.upper()} detected on parameter "
            f"{injection_point.name}"
        )

        evidence = {
            "analysis": analysis.to_dict(),
            "escalation": escalation.to_dict() if escalation else None,
            "confidence": confidence.to_dict(),
            "payload_source": payload_item.source_file,
            "injection_point": injection_point.to_dict()
        }

        return Finding(
            title=title,
            finding_type=finding_type,
            endpoint=self.config.get("target_url", ""),
            method=self.config.get("method", "GET"),
            parameter=injection_point.name,
            location=injection_point.location,
            payload=payload_item.payload,
            confidence=confidence,
            evidence=evidence,
            request_params=request_params,
            request_json_body=request_json_body,
            headers=self.config.get("headers", {}),
            description=self._build_description(
                finding_type=finding_type,
                injection_point=injection_point
            ),
            recommendation=self._build_recommendation(finding_type)
        )

    def _build_description(
        self,
        finding_type: str,
        injection_point: InjectionPoint
    ) -> str:
        """
        Private method.

        Sinh mô tả finding.
        """
        return (
            f"The parameter '{injection_point.name}' at location "
            f"'{injection_point.location}' produced suspicious behavior "
            f"consistent with '{finding_type}'."
        )

    def _build_recommendation(self, finding_type: str) -> str:
        """
        Private method.

        Sinh khuyến nghị theo nhóm lỗi.
        """
        recommendations = {
            "sqli": (
                "Use parameterized queries/prepared statements, validate input type, "
                "and avoid returning raw database error messages."
            ),
            "xss": (
                "Apply context-aware output encoding, sanitize user-controlled input, "
                "and enable a strict Content Security Policy."
            ),
            "path_traversal": (
                "Normalize and validate file paths, use allowlists, and prevent direct "
                "user control over filesystem paths."
            ),
            "command_injection": (
                "Avoid shell execution with user input, use safe APIs, and apply strict "
                "allowlist validation."
            ),
            "idor": (
                "Enforce object-level authorization checks on every request and never "
                "trust user-controlled identifiers."
            ),
            "time_based": (
                "Investigate backend query execution paths and ensure user input cannot "
                "control expensive or blocking operations."
            ),
            "server_error": (
                "Handle exceptions safely, validate inputs, and avoid exposing internal "
                "error details to clients."
            )
        }

        return recommendations.get(
            finding_type,
            "Validate and sanitize all user-controlled input and apply least privilege access controls."
        )

    def _normalize_positive_int(
        self,
        value: Any,
        default: int
    ) -> int:
        """
        Private method.

        Chuẩn hóa số nguyên dương.
        """
        if not isinstance(value, int):
            return default

        if value <= 0:
            return default

        return value

    def _setup_logger(self) -> logging.Logger:
        """
        Private method.

        Tạo logger riêng cho FuzzingEngine.
        """
        logger = logging.getLogger("FuzzingEngine")

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
    Test nhanh Phase 12.

    Nếu localhost:5000 chưa chạy:
        - baseline sẽ fail có kiểm soát
        - engine vẫn sinh report rỗng
        - không crash
    """

    engine = FuzzingEngine(
        max_payloads_per_point=5,
        max_deep_payloads=3,
        max_workers=1
    )

    result = engine.run()

    print("\n===== Fuzzing Summary =====")
    for key, value in result.to_dict().items():
        print(f"{key}: {value}")