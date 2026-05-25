"""
Phase 5: Baseline Collector

Nhiệm vụ:
- Gửi request SẠCH đến target endpoint
- Dùng ConfigManager để lấy target config
- Dùng HTTPClient để gửi request
- Dùng AuthManager để gắn token/cookie nếu có
- Nếu gặp 401/403 thì thử refresh auth một lần
- Sinh BaselineProfile:
    - status_code
    - content_length
    - average_response_time
    - content_type
    - body_hash
    - sample_count
    - url
    - method
- Nếu baseline trả về HTTP >= 400 thì ném exception cảnh báo
- Không để lỗi network làm crash bất ngờ

"""

import hashlib
import logging
from dataclasses import dataclass
from typing import Any, Dict, List, Optional


try:
    from config_manager import ConfigManager
    from http_client import HTTPClient, UnifiedResponse
    from auth_manager import AuthManager
except ImportError:
    from core.config_manager import ConfigManager
    from core.http_client import HTTPClient, UnifiedResponse
    from core.auth_manager import AuthManager


class BaselineCollectionError(Exception):
    """
    Exception riêng cho lỗi thu thập baseline.
    """
    pass


@dataclass
class BaselineProfile:
    """
    BaselineProfile là hồ sơ phản hồi bình thường của endpoint.

    Fields:
        status_code:
            HTTP status code của request sạch.

        content_length:
            Độ dài response body.

        average_response_time:
            Thời gian phản hồi trung bình qua nhiều lần request.

        content_type:
            Content-Type của response.

        body_hash:
            SHA-256 hash của response body.

        sample_count:
            Số lần request baseline thành công.

        url:
            URL được request.

        method:
            HTTP method.

        headers:
            Response headers của mẫu baseline cuối cùng.

        text_preview:
            Một phần body để debug, không lưu toàn bộ tránh quá nặng.
    """

    status_code: int
    content_length: int
    average_response_time: float
    content_type: str
    body_hash: str
    sample_count: int
    url: str
    method: str
    headers: Dict[str, str]
    text_preview: str

    def to_dict(self) -> Dict[str, Any]:
        """
        Convert BaselineProfile sang dict.
        Dùng cho debug, report hoặc truyền sang ResponseAnalyzer ở Phase 8.
        """
        return {
            "status_code": self.status_code,
            "content_length": self.content_length,
            "average_response_time": self.average_response_time,
            "content_type": self.content_type,
            "body_hash": self.body_hash,
            "sample_count": self.sample_count,
            "url": self.url,
            "method": self.method,
            "headers": self.headers,
            "text_preview": self.text_preview
        }


class BaselineCollector:
    """
    Baseline Collector.

    Contract:
    Input:
        - ConfigManager
        - HTTPClient
        - AuthManager

    Output:
        - collect() -> BaselineProfile

    Public methods:
        - collect()
        - collect_once()

    """

    def __init__(
        self,
        config: Optional[ConfigManager] = None,
        http_client: Optional[HTTPClient] = None,
        auth_manager: Optional[AuthManager] = None,
        sample_count: int = 3
    ):
        """
        Khởi tạo BaselineCollector.

        :param config: ConfigManager instance
        :param http_client: HTTPClient instance
        :param auth_manager: AuthManager instance
        :param sample_count: số lần gửi request sạch để lấy trung bình response_time
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

        if not isinstance(sample_count, int) or sample_count <= 0:
            raise BaselineCollectionError("sample_count must be a positive integer.")

        self.sample_count = sample_count

    def collect(self) -> BaselineProfile:
        """
        Public method.

        Gửi nhiều request sạch và tạo BaselineProfile.
        """
        self.logger.info("Starting baseline collection. Sample count: %s", self.sample_count)

        if self.config.get("auth.auth_enabled", False):
            login_success = self.auth_manager.login()

            if not login_success:
                raise BaselineCollectionError(
                    f"Cannot collect baseline because authentication failed: "
                    f"{self.auth_manager.get_auth_state().last_error}"
                )

        successful_responses: List[UnifiedResponse] = []

        for index in range(self.sample_count):
            self.logger.info("Collecting baseline sample %s/%s", index + 1, self.sample_count)

            response = self.collect_once()

            if response.is_error:
                raise BaselineCollectionError(
                    f"Baseline request failed due to network/request error: {response.error}"
                )

            if response.status_code >= 400:
                raise BaselineCollectionError(
                    f"Baseline returned HTTP {response.status_code}. "
                    f"Target may be invalid, unauthorized, or unstable. "
                    f"Body preview: {response.text[:200]}"
                )

            successful_responses.append(response)

        return self._build_baseline_profile(successful_responses)

    def collect_once(self) -> UnifiedResponse:
        """
        Public method.

        Gửi đúng 1 request sạch đến target endpoint.

        """
        method = self.config.get("method", "GET")
        url = self.config.get("target_url")
        headers = self.config.get("headers", {})
        params = self.config.get("params", {})
        json_body = self.config.get("json_body", {})
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
                "Baseline request returned auth error HTTP %s. Trying refresh_auth() once.",
                response.status_code
            )

            refresh_success = self.auth_manager.refresh_auth()

            if not refresh_success:
                self.logger.error("refresh_auth() failed during baseline collection.")
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

    def _build_baseline_profile(
        self,
        responses: List[UnifiedResponse]
    ) -> BaselineProfile:
        """
        Private method.

        Tạo BaselineProfile từ danh sách response thành công.
        """
        if not responses:
            raise BaselineCollectionError("Cannot build baseline profile from empty responses.")

        reference_response = responses[-1]

        response_times = [
            response.response_time
            for response in responses
        ]

        average_response_time = sum(response_times) / len(response_times)

        response_text = reference_response.text or ""
        response_headers = reference_response.headers or {}

        content_type = response_headers.get("Content-Type", "")

        body_hash = self._hash_body(response_text)

        profile = BaselineProfile(
            status_code=reference_response.status_code,
            content_length=len(response_text),
            average_response_time=average_response_time,
            content_type=content_type,
            body_hash=body_hash,
            sample_count=len(responses),
            url=reference_response.url,
            method=reference_response.method,
            headers=response_headers,
            text_preview=response_text[:300]
        )

        self.logger.info(
            "Baseline collected successfully. status=%s length=%s avg_time=%.4fs content_type=%s",
            profile.status_code,
            profile.content_length,
            profile.average_response_time,
            profile.content_type
        )

        return profile

    def _hash_body(self, text: str) -> str:
        """
        Private method.

        Tạo SHA-256 hash cho response body.
        """
        if text is None:
            text = ""

        return hashlib.sha256(text.encode("utf-8", errors="ignore")).hexdigest()

    def _setup_logger(self) -> logging.Logger:
        """
        Private method.

        Tạo logger riêng cho BaselineCollector.
        """
        logger = logging.getLogger("BaselineCollector")

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
    Test nhanh Phase 5.

    Nếu localhost:5000 chưa chạy:
        - Không crash bất ngờ
        - Báo lỗi baseline rõ ràng

    Nếu API chạy và trả HTTP < 400:
        - In ra BaselineProfile
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

        collector = BaselineCollector(
            config=config,
            http_client=client,
            auth_manager=auth,
            sample_count=3
        )

        baseline = collector.collect()

        print("\n Baseline Profile ")
        for key, value in baseline.to_dict().items():
            print(f"{key}: {value}")

    except BaselineCollectionError as error:
        print("\n Baseline Collection Failed ")
        print("error:", error)