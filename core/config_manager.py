"""
Phase 2: Config Manager

Nhiệm vụ:
- Load config/target.json
- Load config/auth_config.json
- Cung cấp ConfigManager dạng Singleton
- Cho phép truy xuất config bằng dot-path:
    config.get("target_url")
    config.get("auth.login_url")
- Validate các field bắt buộc
- Nếu config lỗi: ghi log và dừng chương trình

"""

import json
import logging
import sys
from pathlib import Path
from typing import Any, Dict, Optional


class ConfigError(Exception):
    """
    Exception riêng cho lỗi cấu hình.
    Giúp phân biệt lỗi config với lỗi runtime khác.
    """
    pass


class ConfigManager:
    """
    Singleton Config Manager.

    Contract:
    Input:
        - config/target.json
        - config/auth_config.json

    Output:
        - Object cho phép truy xuất config:
            config.get("target_url")
            config.get("auth.login_url")

    Không module nào được truy cập trực tiếp biến private như _config.
    Các module khác chỉ nên dùng public method:
        - get()
        - get_all()
        - reload()
    """

    _instance = None

    DEFAULT_TARGET_CONFIG_PATH = Path("config/target.json")
    DEFAULT_AUTH_CONFIG_PATH = Path("config/auth_config.json")

    REQUIRED_TARGET_FIELDS = [
        "target_url",
        "method",
        "headers",
        "timeout",
        "verify_ssl"
    ]

    VALID_HTTP_METHODS = {
        "GET",
        "POST",
        "PUT",
        "DELETE",
        "PATCH"
    }

    def __new__(cls, *args, **kwargs):
        """
        Đảm bảo chỉ có duy nhất một instance ConfigManager trong toàn bộ chương trình.
        """
        if cls._instance is None:
            cls._instance = super(ConfigManager, cls).__new__(cls)
            cls._instance._initialized = False
        return cls._instance

    def __init__(
        self,
        target_config_path: Optional[str] = None,
        auth_config_path: Optional[str] = None
    ):
        """
        Khởi tạo ConfigManager.
        """
        if self._initialized:
            return

        self.logger = self._setup_logger()

        self.target_config_path = Path(target_config_path) if target_config_path else self.DEFAULT_TARGET_CONFIG_PATH
        self.auth_config_path = Path(auth_config_path) if auth_config_path else self.DEFAULT_AUTH_CONFIG_PATH

        self._config: Dict[str, Any] = {}

        try:
            self.reload()
            self._initialized = True
        except ConfigError as error:
            self.logger.critical("Config error: %s", error)
            sys.exit(1)
        except Exception as error:
            self.logger.critical("Unexpected error while loading config: %s", error)
            sys.exit(1)

    def _setup_logger(self) -> logging.Logger:
        """
        Tạo logger riêng cho ConfigManager.
        """
        logger = logging.getLogger("ConfigManager")

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

    def reload(self) -> None:
        """
        Public method.

        Reload toàn bộ config từ file.
        """
        target_config = self._load_json_file(self.target_config_path)
        auth_config = self._load_json_file(self.auth_config_path)

        self._validate_target_config(target_config)
        self._validate_auth_config(auth_config)

        self._config = {
            **target_config,
            "auth": auth_config
        }

        self.logger.info("Configuration loaded successfully.")

    def get(self, key_path: str, default: Any = None) -> Any:
        """
        Public method.

        Lấy giá trị config bằng dot-path.

        """
        if not key_path or not isinstance(key_path, str):
            return default

        current_value: Any = self._config

        for key in key_path.split("."):
            if isinstance(current_value, dict) and key in current_value:
                current_value = current_value[key]
            else:
                return default

        return current_value

    def get_all(self) -> Dict[str, Any]:
        """
        Public method.

        Trả về toàn bộ config đã load.
        """
        return dict(self._config)

    def _load_json_file(self, file_path: Path) -> Dict[str, Any]:
        """
        Private method.

        Load một file JSON và trả về dict.

        """
        if not file_path.exists():
            raise ConfigError(f"Missing config file: {file_path}")

        if not file_path.is_file():
            raise ConfigError(f"Config path is not a file: {file_path}")

        try:
            with file_path.open("r", encoding="utf-8") as file:
                data = json.load(file)
        except json.JSONDecodeError as error:
            raise ConfigError(f"Invalid JSON format in {file_path}: {error}") from error
        except OSError as error:
            raise ConfigError(f"Cannot read config file {file_path}: {error}") from error

        if not isinstance(data, dict):
            raise ConfigError(f"Config root must be a JSON object in file: {file_path}")

        return data

    def _validate_target_config(self, config: Dict[str, Any]) -> None:
        """
        Private method.

        Validate config/target.json.

        Required fields:
            - target_url
            - method
            - headers
            - timeout
            - verify_ssl

        """
        self._validate_required_fields(
            config=config,
            required_fields=self.REQUIRED_TARGET_FIELDS,
            config_name="target.json"
        )

        target_url = config.get("target_url")
        method = config.get("method")
        headers = config.get("headers")
        timeout = config.get("timeout")
        verify_ssl = config.get("verify_ssl")

        if not isinstance(target_url, str) or not target_url.strip():
            raise ConfigError("target.json: 'target_url' must be a non-empty string.")

        if not target_url.startswith(("http://", "https://")):
            raise ConfigError("target.json: 'target_url' must start with http:// or https://.")

        if not isinstance(method, str):
            raise ConfigError("target.json: 'method' must be a string.")

        normalized_method = method.upper()

        if normalized_method not in self.VALID_HTTP_METHODS:
            raise ConfigError(
                f"target.json: unsupported HTTP method '{method}'. "
                f"Allowed methods: {sorted(self.VALID_HTTP_METHODS)}"
            )

        config["method"] = normalized_method

        if not isinstance(headers, dict):
            raise ConfigError("target.json: 'headers' must be an object/dict.")

        if not isinstance(timeout, (int, float)) or timeout <= 0:
            raise ConfigError("target.json: 'timeout' must be a positive number.")

        if not isinstance(verify_ssl, bool):
            raise ConfigError("target.json: 'verify_ssl' must be true or false.")

        params = config.get("params", {})
        json_body = config.get("json_body", {})

        if params is not None and not isinstance(params, dict):
            raise ConfigError("target.json: 'params' must be an object/dict if provided.")

        if json_body is not None and not isinstance(json_body, dict):
            raise ConfigError("target.json: 'json_body' must be an object/dict if provided.")

    def _validate_auth_config(self, config: Dict[str, Any]) -> None:
        """
        Private method.

        Validate config/auth_config.json.
        """
        if "auth_enabled" not in config:
            raise ConfigError("auth_config.json: missing required field 'auth_enabled'.")

        auth_enabled = config.get("auth_enabled")

        if not isinstance(auth_enabled, bool):
            raise ConfigError("auth_config.json: 'auth_enabled' must be true or false.")

        if auth_enabled is False:
            return

        required_auth_fields = [
            "auth_type",
            "login_url",
            "method",
            "headers",
            "credentials"
        ]

        self._validate_required_fields(
            config=config,
            required_fields=required_auth_fields,
            config_name="auth_config.json"
        )

        auth_type = config.get("auth_type")
        login_url = config.get("login_url")
        method = config.get("method")
        headers = config.get("headers")
        credentials = config.get("credentials")

        if not isinstance(auth_type, str) or not auth_type.strip():
            raise ConfigError("auth_config.json: 'auth_type' must be a non-empty string.")

        allowed_auth_types = {"bearer", "cookie"}

        if auth_type.lower() not in allowed_auth_types:
            raise ConfigError(
                f"auth_config.json: unsupported auth_type '{auth_type}'. "
                f"Allowed types: {sorted(allowed_auth_types)}"
            )

        config["auth_type"] = auth_type.lower()

        if not isinstance(login_url, str) or not login_url.strip():
            raise ConfigError("auth_config.json: 'login_url' must be a non-empty string.")

        if not login_url.startswith(("http://", "https://")):
            raise ConfigError("auth_config.json: 'login_url' must start with http:// or https://.")

        if not isinstance(method, str):
            raise ConfigError("auth_config.json: 'method' must be a string.")

        normalized_method = method.upper()

        if normalized_method not in self.VALID_HTTP_METHODS:
            raise ConfigError(
                f"auth_config.json: unsupported HTTP method '{method}'. "
                f"Allowed methods: {sorted(self.VALID_HTTP_METHODS)}"
            )

        config["method"] = normalized_method

        if not isinstance(headers, dict):
            raise ConfigError("auth_config.json: 'headers' must be an object/dict.")

        if not isinstance(credentials, dict):
            raise ConfigError("auth_config.json: 'credentials' must be an object/dict.")

        if config["auth_type"] == "bearer":
            self._validate_bearer_auth_config(config)

        if config["auth_type"] == "cookie":
            self._validate_cookie_auth_config(config)

    def _validate_bearer_auth_config(self, config: Dict[str, Any]) -> None:
        """
        Private method.

        Validate riêng cho Bearer Token auth.
        """
        required_fields = [
            "token_json_path",
            "token_prefix",
            "auth_header_name"
        ]

        self._validate_required_fields(
            config=config,
            required_fields=required_fields,
            config_name="auth_config.json"
        )

        for field in required_fields:
            value = config.get(field)
            if not isinstance(value, str) or not value.strip():
                raise ConfigError(f"auth_config.json: '{field}' must be a non-empty string.")

    def _validate_cookie_auth_config(self, config: Dict[str, Any]) -> None:
        """
        Private method.

        Validate riêng cho Cookie auth.

        """
        required_fields = [
            "cookie_name"
        ]

        self._validate_required_fields(
            config=config,
            required_fields=required_fields,
            config_name="auth_config.json"
        )

        cookie_name = config.get("cookie_name")

        if not isinstance(cookie_name, str) or not cookie_name.strip():
            raise ConfigError("auth_config.json: 'cookie_name' must be a non-empty string.")

    def _validate_required_fields(
        self,
        config: Dict[str, Any],
        required_fields: list,
        config_name: str
    ) -> None:
        """
        Private method.

        Kiểm tra danh sách field bắt buộc.

        """
        missing_fields = [
            field for field in required_fields
            if field not in config
        ]

        if missing_fields:
            raise ConfigError(
                f"{config_name}: missing required field(s): {', '.join(missing_fields)}"
            )


if __name__ == "__main__":
    """
    Test nhanh Phase 2.

    Nếu config hợp lệ, sẽ in ra vài giá trị mẫu.
    """
    config = ConfigManager()

    print("target_url:", config.get("target_url"))
    print("method:", config.get("method"))
    print("timeout:", config.get("timeout"))
    print("auth_enabled:", config.get("auth.auth_enabled"))
    print("auth.login_url:", config.get("auth.login_url"))