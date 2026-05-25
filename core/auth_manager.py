"""
Phase 4: Auth Manager

Nhiệm vụ:
- Quản lý authentication/session
- Lấy config từ ConfigManager
- Dùng HTTPClient để login
- Hỗ trợ Bearer Token và Cookie
- Có hàm attach_auth(headers)
- Có cơ chế phát hiện mất auth qua HTTP 401/403
- Có hàm refresh_auth() để login lại
- Không để lỗi network làm tool crash

"""

import json
import logging
from dataclasses import dataclass
from typing import Any, Dict, Optional


try:
    from config_manager import ConfigManager
    from http_client import HTTPClient, UnifiedResponse
except ImportError:
    from core.config_manager import ConfigManager
    from core.http_client import HTTPClient, UnifiedResponse


@dataclass
class AuthState:
    """
    Object mô tả trạng thái xác thực hiện tại.

    Fields:
        auth_enabled:
            Có bật authentication hay không.

        auth_type:
            bearer hoặc cookie.

        is_authenticated:
            Đã login thành công hay chưa.

        token:
            Bearer token nếu auth_type = bearer.

        cookie_name:
            Tên cookie nếu auth_type = cookie.

        cookie_value:
            Giá trị cookie nếu auth_type = cookie.

        last_error:
            Lỗi gần nhất nếu login thất bại.
    """

    auth_enabled: bool
    auth_type: Optional[str] = None
    is_authenticated: bool = False
    token: Optional[str] = None
    cookie_name: Optional[str] = None
    cookie_value: Optional[str] = None
    last_error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """
        Convert AuthState sang dict.
        """
        return {
            "auth_enabled": self.auth_enabled,
            "auth_type": self.auth_type,
            "is_authenticated": self.is_authenticated,
            "token_preview": self._preview_secret(self.token),
            "cookie_name": self.cookie_name,
            "cookie_value_preview": self._preview_secret(self.cookie_value),
            "last_error": self.last_error
        }

    def _preview_secret(self, value: Optional[str]) -> Optional[str]:
        if not value:
            return None

        if len(value) <= 10:
            return "***"

        return f"{value[:6]}...{value[-4:]}"


class AuthManager:
    """
    Auth Manager.

    Contract:
    Input:
        - ConfigManager
        - HTTPClient

    Output:
        - login() -> bool
        - attach_auth(headers: dict) -> dict
        - is_auth_error(response: UnifiedResponse) -> bool
        - refresh_auth() -> bool
        - get_auth_state() -> AuthState
    """

    AUTH_ERROR_STATUS_CODES = {401, 403}

    def __init__(
        self,
        config: Optional[ConfigManager] = None,
        http_client: Optional[HTTPClient] = None
    ):
        """
        Khởi tạo AuthManager.

        :param config: ConfigManager instance
        :param http_client: HTTPClient instance
        """
        self.logger = self._setup_logger()

        self.config = config if config else ConfigManager()

        self.auth_enabled = self.config.get("auth.auth_enabled", False)
        self.auth_type = self.config.get("auth.auth_type")

        self.http_client = http_client if http_client else HTTPClient(
            default_headers=self.config.get("auth.headers", {}),
            timeout=self.config.get("timeout", 10),
            verify_ssl=self.config.get("verify_ssl", False)
        )

        self.state = AuthState(
            auth_enabled=self.auth_enabled,
            auth_type=self.auth_type,
            is_authenticated=False
        )

        if not self.auth_enabled:
            self.logger.info("Authentication is disabled.")
        else:
            self.logger.info("Authentication is enabled. Auth type: %s", self.auth_type)

    def login(self) -> bool:
        """
        Public method.

        Thực hiện login dựa theo auth_config.json.

        """
        if not self.auth_enabled:
            self.state.is_authenticated = True
            self.state.last_error = None
            return True

        try:
            login_url = self.config.get("auth.login_url")
            method = self.config.get("auth.method", "POST")
            headers = self.config.get("auth.headers", {})
            credentials = self.config.get("auth.credentials", {})

            if not login_url:
                return self._fail_login("Missing auth.login_url")

            if not isinstance(credentials, dict):
                return self._fail_login("auth.credentials must be a dict")

            self.logger.info("Attempting login: %s %s", method, login_url)

            response = self.http_client.request(
                method=method,
                url=login_url,
                headers=headers,
                json_body=credentials
            )

            if response.is_error:
                return self._fail_login(f"Login request failed: {response.error}")

            if response.status_code >= 400:
                return self._fail_login(
                    f"Login failed with HTTP {response.status_code}. Body preview: {response.text[:200]}"
                )

            if self.auth_type == "bearer":
                return self._handle_bearer_login(response)

            if self.auth_type == "cookie":
                return self._handle_cookie_login(response)

            return self._fail_login(f"Unsupported auth_type: {self.auth_type}")

        except Exception as error:
            self.logger.exception("Unexpected error during login.")
            return self._fail_login(f"Unexpected login error: {error}")

    def attach_auth(self, headers: Optional[Dict[str, str]] = None) -> Dict[str, str]:
        """
        Public method.

        Gắn thông tin auth vào headers.

        """
        final_headers = dict(headers) if headers else {}

        if not self.auth_enabled:
            return final_headers

        if not self.state.is_authenticated:
            self.logger.warning("attach_auth() called but user is not authenticated.")
            return final_headers

        if self.auth_type == "bearer":
            auth_header_name = self.config.get("auth.auth_header_name", "Authorization")
            token_prefix = self.config.get("auth.token_prefix", "Bearer")

            if self.state.token:
                final_headers[auth_header_name] = f"{token_prefix} {self.state.token}"

            return final_headers

        if self.auth_type == "cookie":
            if self.state.cookie_name and self.state.cookie_value:
                existing_cookie = final_headers.get("Cookie")

                new_cookie = f"{self.state.cookie_name}={self.state.cookie_value}"

                if existing_cookie:
                    final_headers["Cookie"] = f"{existing_cookie}; {new_cookie}"
                else:
                    final_headers["Cookie"] = new_cookie

            return final_headers

        return final_headers

    def is_auth_error(self, response: UnifiedResponse) -> bool:
        """
        Public method.

        Kiểm tra response có phải lỗi xác thực hay không.

        :param response: UnifiedResponse từ HTTPClient
        """
        if response is None:
            return False

        return response.status_code in self.AUTH_ERROR_STATUS_CODES

    def refresh_auth(self) -> bool:
        """
        Public method.

        Login lại khi token/cookie hết hạn.

        """
        if not self.auth_enabled:
            self.logger.info("refresh_auth() skipped because authentication is disabled.")
            return True

        self.logger.info("Refreshing authentication...")

        self._clear_auth_state()

        return self.login()

    def get_auth_state(self) -> AuthState:
        """
        Public method.

        Trả về trạng thái auth hiện tại.

        """
        return self.state

    def _handle_bearer_login(self, response: UnifiedResponse) -> bool:
        """
        Private method.

        Xử lý login Bearer Token.

        Token được bóc từ JSON body dựa theo token_json_path.

        """
        token_json_path = self.config.get("auth.token_json_path")

        if not token_json_path:
            return self._fail_login("Missing auth.token_json_path for bearer auth")

        try:
            response_json = json.loads(response.text)
        except json.JSONDecodeError:
            return self._fail_login("Login response is not valid JSON; cannot extract bearer token")

        token = self._extract_value_by_dot_path(response_json, token_json_path)

        if not token or not isinstance(token, str):
            return self._fail_login(
                f"Cannot extract bearer token from path: {token_json_path}"
            )

        self.state.is_authenticated = True
        self.state.token = token
        self.state.cookie_name = None
        self.state.cookie_value = None
        self.state.last_error = None

        self.logger.info("Bearer token login successful.")

        return True

    def _handle_cookie_login(self, response: UnifiedResponse) -> bool:
        """
        Private method.

        Xử lý login Cookie.

        Cách lấy cookie:
        - Ưu tiên lấy từ response.headers['Set-Cookie']
        - Tìm cookie_name trong chuỗi Set-Cookie
        """
        cookie_name = self.config.get("auth.cookie_name")

        if not cookie_name:
            return self._fail_login("Missing auth.cookie_name for cookie auth")

        set_cookie_header = response.headers.get("Set-Cookie", "")

        if not set_cookie_header:
            return self._fail_login("Login response does not contain Set-Cookie header")

        cookie_value = self._extract_cookie_value(
            set_cookie_header=set_cookie_header,
            cookie_name=cookie_name
        )

        if not cookie_value:
            return self._fail_login(f"Cannot extract cookie value for cookie_name: {cookie_name}")

        self.state.is_authenticated = True
        self.state.token = None
        self.state.cookie_name = cookie_name
        self.state.cookie_value = cookie_value
        self.state.last_error = None

        self.logger.info("Cookie login successful. Cookie name: %s", cookie_name)

        return True

    def _extract_value_by_dot_path(
        self,
        data: Dict[str, Any],
        dot_path: str
    ) -> Any:
        """
        Private method.

        Lấy value từ dict bằng dot-path.
        """
        current_value: Any = data

        for key in dot_path.split("."):
            if isinstance(current_value, dict) and key in current_value:
                current_value = current_value[key]
            else:
                return None

        return current_value

    def _extract_cookie_value(
        self,
        set_cookie_header: str,
        cookie_name: str
    ) -> Optional[str]:
        """
        Private method.

        Bóc cookie value từ Set-Cookie header.

        """
        if not set_cookie_header or not cookie_name:
            return None

        cookie_parts = set_cookie_header.split(";")

        for part in cookie_parts:
            part = part.strip()

            if part.startswith(f"{cookie_name}="):
                return part.split("=", 1)[1]

        return None

    def _clear_auth_state(self) -> None:
        """
        Private method.

        Xóa token/cookie hiện tại trước khi login lại.
        """
        self.state.is_authenticated = False
        self.state.token = None
        self.state.cookie_name = None
        self.state.cookie_value = None
        self.state.last_error = None

    def _fail_login(self, message: str) -> bool:
        """
        Private method.

        Ghi nhận login thất bại, log lỗi, trả về False.
        """
        self.state.is_authenticated = False
        self.state.last_error = message

        self.logger.error("Authentication failed: %s", message)

        return False

    def _setup_logger(self) -> logging.Logger:
        """
        Private method.

        Tạo logger riêng cho AuthManager.
        """
        logger = logging.getLogger("AuthManager")

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
    Test nhanh Phase 4.
    
    Nếu localhost:5000 chưa chạy:
        - Không crash
        - Login thất bại có kiểm soát
        - In ra AuthState với last_error

    Nếu auth_enabled = false:
        - login() trả True
        - is_authenticated = True
    """

    config = ConfigManager()

    client = HTTPClient(
        default_headers=config.get("headers", {}),
        timeout=config.get("timeout", 10),
        verify_ssl=config.get("verify_ssl", False)
    )

    auth_manager = AuthManager(
        config=config,
        http_client=client
    )

    login_success = auth_manager.login()

    print("\n Auth Manager Test ")
    print("login_success:", login_success)
    print("auth_state:", auth_manager.get_auth_state().to_dict())

    original_headers = {
        "Accept": "application/json"
    }

    headers_with_auth = auth_manager.attach_auth(original_headers)

    print("headers_after_attach_auth:", headers_with_auth)