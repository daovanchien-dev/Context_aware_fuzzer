"""
Phase 9: Escalation Engine

Nhiệm vụ:
- Chỉ chạy khi ResponseAnalyzer báo is_suspicious == True
- Lấy deep payload từ PayloadGenerator
- Mutate đúng tham số trong query params hoặc json body
- Gửi lại request bằng HTTPClient
- Nếu gặp 401/403 thì refresh auth một lần
- Phân tích lại response bằng ResponseAnalyzer
- Trả về EscalationResult để Phase 10 chấm confidence score

"""

import copy
import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


try:
    from config_manager import ConfigManager
    from http_client import HTTPClient, UnifiedResponse
    from auth_manager import AuthManager
    from baseline_collector import BaselineProfile
    from parameter_classifier import InjectionPoint
    from payload_generator import PayloadGenerator, PayloadItem
    from response_analyzer import ResponseAnalyzer, AnalysisResult
except ImportError:
    from core.config_manager import ConfigManager
    from core.http_client import HTTPClient, UnifiedResponse
    from core.auth_manager import AuthManager
    from core.baseline_collector import BaselineProfile
    from core.parameter_classifier import InjectionPoint
    from core.payload_generator import PayloadGenerator, PayloadItem
    from core.response_analyzer import ResponseAnalyzer, AnalysisResult


@dataclass
class EscalationAttempt:
    """
    Một lần thử deep payload.

    Fields:
        payload:
            PayloadItem đã dùng.

        response:
            UnifiedResponse trả về từ HTTPClient.

        analysis:
            AnalysisResult sau khi phân tích response.

        request_params:
            Query params sau khi bị mutate.

        request_json_body:
            JSON body sau khi bị mutate.
    """

    payload: PayloadItem
    response: UnifiedResponse
    analysis: AnalysisResult
    request_params: Dict[str, Any]
    request_json_body: Dict[str, Any]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "payload": self.payload.to_dict(),
            "response": self.response.to_dict(),
            "analysis": self.analysis.to_dict(),
            "request_params": self.request_params,
            "request_json_body": self.request_json_body
        }


@dataclass
class EscalationResult:
    """
    Kết quả Escalation Engine.

    Fields:
        escalated:
            Có thực hiện escalation hay không.

        confirmed:
            Có xác nhận được dấu hiệu bất thường mạnh hơn hay không.

        vulnerability_family:
            Nhóm lỗ hổng đang xác minh.

        tested_payloads:
            Danh sách payload đã thử.

        confirmation_reasons:
            Lý do xác nhận.

        attempts:
            Danh sách EscalationAttempt.

        best_analysis:
            AnalysisResult tốt nhất/đáng nghi nhất.
    """

    escalated: bool
    confirmed: bool
    vulnerability_family: str
    tested_payloads: List[str] = field(default_factory=list)
    confirmation_reasons: List[str] = field(default_factory=list)
    attempts: List[EscalationAttempt] = field(default_factory=list)
    best_analysis: Optional[AnalysisResult] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "escalated": self.escalated,
            "confirmed": self.confirmed,
            "vulnerability_family": self.vulnerability_family,
            "tested_payloads": self.tested_payloads,
            "confirmation_reasons": self.confirmation_reasons,
            "attempts": [
                attempt.to_dict()
                for attempt in self.attempts
            ],
            "best_analysis": self.best_analysis.to_dict() if self.best_analysis else None
        }


class EscalationEngine:
    """
    Escalation Engine.

    Contract:
    Input:
        - BaselineProfile
        - InjectionPoint
        - AnalysisResult 

    Output:
        - EscalationResult

    Public methods:
        - escalate()

    """

    def __init__(
        self,
        config: Optional[ConfigManager] = None,
        http_client: Optional[HTTPClient] = None,
        auth_manager: Optional[AuthManager] = None,
        payload_generator: Optional[PayloadGenerator] = None,
        response_analyzer: Optional[ResponseAnalyzer] = None,
        max_deep_payloads: int = 3
    ):
        """
        Khởi tạo EscalationEngine.

        :param config: ConfigManager
        :param http_client: HTTPClient
        :param auth_manager: AuthManager
        :param payload_generator: PayloadGenerator
        :param response_analyzer: ResponseAnalyzer
        :param max_deep_payloads: số deep payload tối đa thử trên mỗi InjectionPoint
        """
        self.logger = self._setup_logger()

        self.config = config if config else ConfigManager()

        self.http_client = http_client if http_client else HTTPClient(
            default_headers=self.config.get("headers", {}),
            timeout=self.config.get("timeout", 10),
            verify_ssl=self.config.get("verify_ssl", False)
        )

        self.auth_manager = auth_manager if auth_manager else AuthManager(
            config=self.config,
            http_client=self.http_client
        )

        self.payload_generator = payload_generator if payload_generator else PayloadGenerator()

        self.response_analyzer = response_analyzer if response_analyzer else ResponseAnalyzer()

        if not isinstance(max_deep_payloads, int) or max_deep_payloads <= 0:
            max_deep_payloads = 5

        self.max_deep_payloads = max_deep_payloads

    def escalate(
        self,
        baseline: BaselineProfile,
        injection_point: InjectionPoint,
        initial_analysis: AnalysisResult
    ) -> EscalationResult:
        """
        Public method.

        Thực hiện escalation nếu initial_analysis đáng nghi.

        """
        if not initial_analysis or not initial_analysis.is_suspicious:
            self.logger.info("Escalation skipped because initial analysis is not suspicious.")

            return EscalationResult(
                escalated=False,
                confirmed=False,
                vulnerability_family="unknown",
                confirmation_reasons=[
                    "Initial analysis is not suspicious"
                ]
            )

        vulnerability_family = initial_analysis.detected_family or "unknown"

        if vulnerability_family in {"unknown", "network"}:
            self.logger.info("Escalation skipped because detected family is not actionable: %s", vulnerability_family)

            return EscalationResult(
                escalated=False,
                confirmed=False,
                vulnerability_family=vulnerability_family,
                confirmation_reasons=[
                    f"Detected family is not actionable: {vulnerability_family}"
                ]
            )

        deep_payloads = self.payload_generator.get_deep_payloads(
            param_type=injection_point.param_type,
            vulnerability_family=vulnerability_family
        )

        if not deep_payloads:
            self.logger.warning(
                "No deep payloads found for family=%s param_type=%s",
                vulnerability_family,
                injection_point.param_type
            )

            return EscalationResult(
                escalated=False,
                confirmed=False,
                vulnerability_family=vulnerability_family,
                confirmation_reasons=[
                    "No deep payloads available"
                ]
            )

        deep_payloads = deep_payloads[:self.max_deep_payloads]

        attempts: List[EscalationAttempt] = []
        tested_payloads: List[str] = []
        confirmation_reasons: List[str] = []
        best_analysis: Optional[AnalysisResult] = None

        self.logger.info(
            "Starting escalation. family=%s injection_point=%s payload_count=%s",
            vulnerability_family,
            injection_point.path,
            len(deep_payloads)
        )

        for payload_item in deep_payloads:
            tested_payloads.append(payload_item.payload)

            try:
                request_params, request_json_body = self._build_mutated_request_data(
                    injection_point=injection_point,
                    payload=payload_item.payload
                )

                response = self._send_escalation_request(
                    params=request_params,
                    json_body=request_json_body
                )

                analysis = self.response_analyzer.analyze(
                    baseline=baseline,
                    fuzzed_response=response,
                    payload=payload_item.payload
                )

                attempt = EscalationAttempt(
                    payload=payload_item,
                    response=response,
                    analysis=analysis,
                    request_params=request_params,
                    request_json_body=request_json_body
                )

                attempts.append(attempt)

                if self._is_better_analysis(analysis, best_analysis):
                    best_analysis = analysis

                if self._is_confirmed(
                    vulnerability_family=vulnerability_family,
                    analysis=analysis,
                    response=response
                ):
                    confirmation_reasons.extend(analysis.anomaly_reasons)

                    self.logger.info(
                        "Escalation confirmed. family=%s payload=%s",
                        vulnerability_family,
                        payload_item.payload
                    )

                    return EscalationResult(
                        escalated=True,
                        confirmed=True,
                        vulnerability_family=vulnerability_family,
                        tested_payloads=tested_payloads,
                        confirmation_reasons=list(dict.fromkeys(confirmation_reasons)),
                        attempts=attempts,
                        best_analysis=best_analysis
                    )

            except Exception as error:
                self.logger.exception(
                    "Unexpected error during escalation with payload '%s': %s",
                    payload_item.payload,
                    error
                )

        return EscalationResult(
            escalated=True,
            confirmed=False,
            vulnerability_family=vulnerability_family,
            tested_payloads=tested_payloads,
            confirmation_reasons=[
                "Deep payloads were tested but no stronger confirmation was found"
            ],
            attempts=attempts,
            best_analysis=best_analysis
        )

    def _build_mutated_request_data(
        self,
        injection_point: InjectionPoint,
        payload: str
    ) -> tuple[Dict[str, Any], Dict[str, Any]]:
        """
        Private method.

        Tạo params/json_body mới bằng cách thay đúng tham số cần fuzz.

        Hỗ trợ:
            query.id
            json.name
            json.profile.user_id
        """
        original_params = copy.deepcopy(self.config.get("params", {}))
        original_json_body = copy.deepcopy(self.config.get("json_body", {}))

        if not isinstance(original_params, dict):
            original_params = {}

        if not isinstance(original_json_body, dict):
            original_json_body = {}

        location = injection_point.location
        path = injection_point.path

        if location == "query":
            original_params[injection_point.name] = payload
            return original_params, original_json_body

        if location == "json":
            if path and path.startswith("json."):
                json_path = path.replace("json.", "", 1).split(".")
                self._set_nested_value(
                    data=original_json_body,
                    path_parts=json_path,
                    value=payload
                )
            else:
                original_json_body[injection_point.name] = payload

            return original_params, original_json_body

        self.logger.warning("Unknown injection point location: %s", location)

        return original_params, original_json_body

    def _set_nested_value(
        self,
        data: Dict[str, Any],
        path_parts: List[str],
        value: Any
    ) -> None:
        """
        Private method.

        Set giá trị trong JSON nested dict.

        """
        if not path_parts:
            return

        current = data

        for part in path_parts[:-1]:
            if part not in current or not isinstance(current[part], dict):
                current[part] = {}

            current = current[part]

        current[path_parts[-1]] = value

    def _send_escalation_request(
        self,
        params: Dict[str, Any],
        json_body: Dict[str, Any]
    ) -> UnifiedResponse:
        """
        Private method.

        Gửi request escalation.
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
                "Escalation request returned auth error HTTP %s. Trying refresh_auth() once.",
                response.status_code
            )

            refresh_success = self.auth_manager.refresh_auth()

            if not refresh_success:
                self.logger.error("refresh_auth() failed during escalation.")
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

    def _is_confirmed(
        self,
        vulnerability_family: str,
        analysis: AnalysisResult,
        response: UnifiedResponse
    ) -> bool:
        """
        Private method.

        Xác định escalation có xác nhận được nghi vấn không.

        """
        if response.is_error:
            return False

        if not analysis.is_suspicious:
            return False

        if analysis.detected_family == vulnerability_family:
            return True

        evidence = analysis.evidence or {}

        if vulnerability_family == "sqli" and evidence.get("sql_error_pattern"):
            return True

        if vulnerability_family == "xss" and evidence.get("reflected_payload"):
            return True

        if vulnerability_family == "path_traversal" and evidence.get("path_traversal_pattern"):
            return True

        if vulnerability_family == "command_injection" and evidence.get("command_injection_pattern"):
            return True

        if vulnerability_family == "time_based" and evidence.get("time_anomaly", {}).get("is_anomaly"):
            return True

        if vulnerability_family == "server_error" and evidence.get("status_code_changed"):
            return True

        return False

    def _is_better_analysis(
        self,
        current: AnalysisResult,
        best: Optional[AnalysisResult]
    ) -> bool:
        """
        Private method.

        Chọn analysis tốt hơn dựa vào số lượng anomaly reason.
        """
        if current is None:
            return False

        if best is None:
            return True

        return len(current.anomaly_reasons) > len(best.anomaly_reasons)

    def _setup_logger(self) -> logging.Logger:
        """
        Private method.

        Tạo logger riêng cho EscalationEngine.
        """
        logger = logging.getLogger("EscalationEngine")

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
    Test nhanh Phase 9.

    """

    try:
        config = ConfigManager()

        client = HTTPClient(
            default_headers=config.get("headers", {}),
            timeout=config.get("timeout", 10),
            verify_ssl=config.get("verify_ssl", False)
        )

        auth = AuthManager(
            config=config,
            http_client=client
        )

        payload_generator = PayloadGenerator()

        analyzer = ResponseAnalyzer()

        engine = EscalationEngine(
            config=config,
            http_client=client,
            auth_manager=auth,
            payload_generator=payload_generator,
            response_analyzer=analyzer,
            max_deep_payloads=3
        )

        fake_baseline = BaselineProfile(
            status_code=200,
            content_length=28,
            average_response_time=0.05,
            content_type="application/json",
            body_hash="dummy_hash",
            sample_count=3,
            url=config.get("target_url", "http://localhost:5000/api/users"),
            method=config.get("method", "GET"),
            headers={
                "Content-Type": "application/json"
            },
            text_preview='{"id":1,"name":"admin"}'
        )

        fake_injection_point = InjectionPoint(
            name="id",
            location="query",
            param_type="number",
            original_value="1",
            risk_tags=[
                "numeric_input",
                "idor_candidate"
            ],
            path="query.id"
        )

        fake_initial_analysis = AnalysisResult(
            is_suspicious=True,
            anomaly_reasons=[
                "SQL error pattern detected: SQL syntax"
            ],
            detected_family="sqli",
            evidence={
                "sql_error_pattern": "SQL syntax"
            }
        )

        result = engine.escalate(
            baseline=fake_baseline,
            injection_point=fake_injection_point,
            initial_analysis=fake_initial_analysis
        )

        print("\n Escalation Result ")
        for key, value in result.to_dict().items():
            print(f"{key}: {value}")

    except Exception as error:
        print("\n Escalation Engine Test Failed ")
        print("error:", error)