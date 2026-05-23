"""
Phase 3: HTTP Client

Nhiệm vụ:
- Wrap thư viện requests
- Hỗ trợ GET / POST / PUT / DELETE / PATCH
- Tự động gắn headers tiêu chuẩn
- Xử lý Timeout, ConnectionError, RequestException
- Không để tool crash khi request lỗi
- Trả về Unified Response Object thống nhất

Module này KHÔNG xử lý login.
Module này KHÔNG tự refresh token.
Auth sẽ được xử lý ở Phase 4.
"""

import logging
import time
from dataclasses import dataclass
from typing import Any, Dict, Optional

import requests
from requests import Response
from requests.exceptions import Timeout, ConnectionError, RequestException


@dataclass
class UnifiedResponse:
    """
    Unified Response Object.

    Đây là object chuẩn mà các module sau sẽ dùng.

    Fields:
        status_code:
            HTTP status code.
            Nếu request lỗi network thì status_code = 0.

        response_time:
            Thời gian phản hồi tính bằng giây.

        text:
            Response body dạng text.
            Nếu lỗi network thì text = "".

        headers:
            Response headers dạng dict.

        url:
            URL đã request.

        method:
            HTTP method đã dùng.

        error:
            Nội dung lỗi nếu request thất bại.
            Nếu không lỗi thì error = None.

        is_error:
            True nếu lỗi network hoặc lỗi request-level.
            False nếu request gửi được tới server.
    """

    status_code: int
    response_time: float
    text: str
    headers: Dict[str, str]
    url: str
    method: str
    error: Optional[str] = None
    is_error: bool = False

    def to_dict(self) -> Dict[str, Any]:
        """
        Convert UnifiedResponse sang dict.

        Dùng cho:
        - Logging
        - Report
        - Debug
        - Module Response Analyzer ở Phase 8

        :return: dict
        """
        return {
            "status_code": self.status_code,
            "response_time": self.response_time,
            "text": self.text,
            "headers": self.headers,
            "url": self.url,
            "method": self.method,
            "error": self.error,
            "is_error": self.is_error
        }


class HTTPClient:
    """
    HTTP Client wrapper.

    Contract:
    ---------
    Input:
        - method
        - url
        - headers
        - params
        - json_body
        - timeout
        - verify_ssl

    Output:
        - UnifiedResponse

    Public methods:
        - request()
        - get()
        - post()
        - put()
        - delete()
        - patch()

    Các module khác KHÔNG gọi private method.
    """

    DEFAULT_HEADERS = {
        "User-Agent": "ContextAwareFuzzer/1.0",
        "Accept": "application/json, text/plain, */*",
        "Connection": "close"
    }

    VALID_METHODS = {
        "GET",
        "POST",
        "PUT",
        "DELETE",
        "PATCH"
    }

    def __init__(
        self,
        default_headers: Optional[Dict[str, str]] = None,
        timeout: int | float = 10,
        verify_ssl: bool = False
    ):
        """
        Khởi tạo HTTPClient.

        :param default_headers: headers mặc định
        :param timeout: timeout mặc định tính bằng giây
        :param verify_ssl: có verify SSL hay không
        """
        self.logger = self._setup_logger()

        self.default_headers = dict(self.DEFAULT_HEADERS)

        if default_headers:
            self.default_headers.update(default_headers)

        self.timeout = timeout
        self.verify_ssl = verify_ssl

        self.session = requests.Session()
        self.session.headers.update(self.default_headers)

    def request(
        self,
        method: str,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        params: Optional[Dict[str, Any]] = None,
        json_body: Optional[Dict[str, Any]] = None,
        data: Optional[Any] = None,
        timeout: Optional[int | float] = None,
        verify_ssl: Optional[bool] = None
    ) -> UnifiedResponse:
        """
        Public method chính để gửi HTTP request.

        :param method: HTTP method
        :param url: target URL
        :param headers: headers bổ sung
        :param params: URL query params
        :param json_body: JSON body
        :param data: raw/form data nếu cần
        :param timeout: timeout override
        :param verify_ssl: SSL verify override
        :return: UnifiedResponse
        """
        method = self._normalize_method(method)

        if method not in self.VALID_METHODS:
            error_message = f"Unsupported HTTP method: {method}"
            self.logger.error(error_message)

            return self._build_error_response(
                method=method,
                url=url,
                error=error_message,
                response_time=0.0
            )

        if not self._is_valid_url(url):
            error_message = f"Invalid URL: {url}"
            self.logger.error(error_message)

            return self._build_error_response(
                method=method,
                url=url,
                error=error_message,
                response_time=0.0
            )

        request_headers = self._merge_headers(headers)

        final_timeout = timeout if timeout is not None else self.timeout
        final_verify_ssl = verify_ssl if verify_ssl is not None else self.verify_ssl

        start_time = time.perf_counter()

        try:
            self.logger.info("%s %s", method, url)

            response = self.session.request(
                method=method,
                url=url,
                headers=request_headers,
                params=params,
                json=json_body,
                data=data,
                timeout=final_timeout,
                verify=final_verify_ssl,
                allow_redirects=True
            )

            response_time = time.perf_counter() - start_time

            return self._build_success_response(
                method=method,
                url=url,
                response=response,
                response_time=response_time
            )

        except Timeout as error:
            response_time = time.perf_counter() - start_time
            error_message = f"Timeout: {error}"

            self.logger.warning("%s %s failed: %s", method, url, error_message)

            return self._build_error_response(
                method=method,
                url=url,
                error=error_message,
                response_time=response_time
            )

        except ConnectionError as error:
            response_time = time.perf_counter() - start_time
            error_message = f"ConnectionError: {error}"

            self.logger.warning("%s %s failed: %s", method, url, error_message)

            return self._build_error_response(
                method=method,
                url=url,
                error=error_message,
                response_time=response_time
            )

        except RequestException as error:
            response_time = time.perf_counter() - start_time
            error_message = f"RequestException: {error}"

            self.logger.warning("%s %s failed: %s", method, url, error_message)

            return self._build_error_response(
                method=method,
                url=url,
                error=error_message,
                response_time=response_time
            )

        except Exception as error:
            response_time = time.perf_counter() - start_time
            error_message = f"UnexpectedError: {error}"

            self.logger.exception("%s %s crashed unexpectedly", method, url)

            return self._build_error_response(
                method=method,
                url=url,
                error=error_message,
                response_time=response_time
            )

    def get(
        self,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        params: Optional[Dict[str, Any]] = None,
        timeout: Optional[int | float] = None,
        verify_ssl: Optional[bool] = None
    ) -> UnifiedResponse:
        """
        Gửi GET request.
        """
        return self.request(
            method="GET",
            url=url,
            headers=headers,
            params=params,
            timeout=timeout,
            verify_ssl=verify_ssl
        )

    def post(
        self,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        params: Optional[Dict[str, Any]] = None,
        json_body: Optional[Dict[str, Any]] = None,
        data: Optional[Any] = None,
        timeout: Optional[int | float] = None,
        verify_ssl: Optional[bool] = None
    ) -> UnifiedResponse:
        """
        Gửi POST request.
        """
        return self.request(
            method="POST",
            url=url,
            headers=headers,
            params=params,
            json_body=json_body,
            data=data,
            timeout=timeout,
            verify_ssl=verify_ssl
        )

    def put(
        self,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        params: Optional[Dict[str, Any]] = None,
        json_body: Optional[Dict[str, Any]] = None,
        data: Optional[Any] = None,
        timeout: Optional[int | float] = None,
        verify_ssl: Optional[bool] = None
    ) -> UnifiedResponse:
        """
        Gửi PUT request.
        """
        return self.request(
            method="PUT",
            url=url,
            headers=headers,
            params=params,
            json_body=json_body,
            data=data,
            timeout=timeout,
            verify_ssl=verify_ssl
        )

    def delete(
        self,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        params: Optional[Dict[str, Any]] = None,
        json_body: Optional[Dict[str, Any]] = None,
        timeout: Optional[int | float] = None,
        verify_ssl: Optional[bool] = None
    ) -> UnifiedResponse:
        """
        Gửi DELETE request.
        """
        return self.request(
            method="DELETE",
            url=url,
            headers=headers,
            params=params,
            json_body=json_body,
            timeout=timeout,
            verify_ssl=verify_ssl
        )

    def patch(
        self,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        params: Optional[Dict[str, Any]] = None,
        json_body: Optional[Dict[str, Any]] = None,
        data: Optional[Any] = None,
        timeout: Optional[int | float] = None,
        verify_ssl: Optional[bool] = None
    ) -> UnifiedResponse:
        """
        Gửi PATCH request.
        """
        return self.request(
            method="PATCH",
            url=url,
            headers=headers,
            params=params,
            json_body=json_body,
            data=data,
            timeout=timeout,
            verify_ssl=verify_ssl
        )

    def _setup_logger(self) -> logging.Logger:
        """
        Private method.

        Tạo logger riêng cho HTTPClient.
        """
        logger = logging.getLogger("HTTPClient")

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

    def _normalize_method(self, method: str) -> str:
        """
        Private method.

        Chuẩn hóa HTTP method về uppercase.
        """
        if not isinstance(method, str):
            return ""

        return method.strip().upper()

    def _is_valid_url(self, url: str) -> bool:
        """
        Private method.

        Kiểm tra URL cơ bản.
        """
        if not isinstance(url, str):
            return False

        if not url.strip():
            return False

        return url.startswith(("http://", "https://"))

    def _merge_headers(
        self,
        headers: Optional[Dict[str, str]]
    ) -> Dict[str, str]:
        """
        Private method.

        Merge default headers với custom headers.

        Custom headers sẽ override default headers nếu trùng key.
        """
        merged_headers = dict(self.default_headers)

        if headers:
            merged_headers.update(headers)

        return merged_headers

    def _build_success_response(
        self,
        method: str,
        url: str,
        response: Response,
        response_time: float
    ) -> UnifiedResponse:
        """
        Private method.

        Build UnifiedResponse cho request thành công ở mức network.
        HTTP 4xx/5xx vẫn được xem là response hợp lệ,
        không phải network error.
        """
        return UnifiedResponse(
            status_code=response.status_code,
            response_time=response_time,
            text=response.text or "",
            headers=dict(response.headers),
            url=str(response.url) if response.url else url,
            method=method,
            error=None,
            is_error=False
        )

    def _build_error_response(
        self,
        method: str,
        url: str,
        error: str,
        response_time: float
    ) -> UnifiedResponse:
        """
        Private method.

        Build UnifiedResponse cho lỗi network hoặc lỗi request-level.
        """
        return UnifiedResponse(
            status_code=0,
            response_time=response_time,
            text="",
            headers={},
            url=url,
            method=method,
            error=error,
            is_error=True
        )


if __name__ == "__main__":
    """
    Test nhanh Phase 3.

    Chạy:
        python core/http_client.py

    Điều kiện:
        - config/target.json đã hợp lệ từ Phase 2
        - Nếu localhost:5000 chưa chạy, vẫn KHÔNG crash.
          Nó sẽ trả về UnifiedResponse với is_error=True.
    """

    try:
        from config_manager import ConfigManager
    except ImportError:
        from core.config_manager import ConfigManager

    config = ConfigManager()

    client = HTTPClient(
        default_headers=config.get("headers", {}),
        timeout=config.get("timeout", 10),
        verify_ssl=config.get("verify_ssl", False)
    )

    response = client.request(
        method=config.get("method", "GET"),
        url=config.get("target_url"),
        headers=config.get("headers", {}),
        params=config.get("params", {}),
        json_body=config.get("json_body", {})
    )

    print("\n===== Unified Response =====")
    print("status_code:", response.status_code)
    print("response_time:", response.response_time)
    print("headers:", response.headers)
    print("text_preview:", response.text[:300])
    print("error:", response.error)
    print("is_error:", response.is_error)