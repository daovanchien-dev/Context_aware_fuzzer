"""
Phase 6: Parameter Classifier

Nhiệm vụ:
- Nhận đầu vào là URL params và JSON body
- Phân loại từng tham số:
    - number
    - string
    - boolean
    - null
    - array
    - object
    - unknown
- Trả ra danh sách InjectionPoint
- Loại bỏ tham số nhạy cảm:
    - password
    - csrf_token
    - access_token
    - refresh_token
    - authorization
    - cookie
    - secret
    - api_key

"""

import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class InjectionPoint:
    """
    InjectionPoint mô tả một vị trí có thể fuzz.

    Fields:
        name:
            Tên tham số, ví dụ: id, name, email.

        location:
            Vị trí tham số:
                - query
                - json

        param_type:
            Kiểu dữ liệu đã phân loại:
                - number
                - string
                - boolean
                - null
                - array
                - object
                - unknown

        original_value:
            Giá trị ban đầu của tham số.

        risk_tags:
            Danh sách nhãn rủi ro hỗ trợ Payload Generator và Analyzer sau này.

        path:
            Đường dẫn đầy đủ của tham số.
            Ví dụ:
                query.id
                json.user.profile.name
    """

    name: str
    location: str
    param_type: str
    original_value: Any
    risk_tags: List[str] = field(default_factory=list)
    path: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """
        Convert InjectionPoint sang dict.
        """
        return {
            "name": self.name,
            "location": self.location,
            "param_type": self.param_type,
            "original_value": self.original_value,
            "risk_tags": self.risk_tags,
            "path": self.path
        }


class ParameterClassifier:
    """
    Parameter Classifier.

    Contract:
    Input:
        - params: dict
        - json_body: dict

    Output:
        - List[InjectionPoint]

    Public methods:
        - classify(params, json_body)

    """

    SENSITIVE_KEYWORDS = {
        "password",
        "passwd",
        "pwd",
        "csrf",
        "csrf_token",
        "xsrf",
        "xsrf_token",
        "token",
        "access_token",
        "refresh_token",
        "authorization",
        "auth",
        "cookie",
        "session",
        "sessionid",
        "secret",
        "client_secret",
        "api_key",
        "apikey",
        "private_key"
    }

    ID_LIKE_KEYWORDS = {
        "id",
        "user_id",
        "uid",
        "account_id",
        "order_id",
        "product_id",
        "post_id",
        "comment_id",
        "role_id",
        "group_id",
        "tenant_id"
    }

    BOOLEAN_LIKE_STRINGS = {
        "true",
        "false",
        "yes",
        "no",
        "on",
        "off",
        "0",
        "1"
    }

    def __init__(self):
        """
        Khởi tạo ParameterClassifier.
        """
        self.logger = self._setup_logger()

    def classify(
        self,
        params: Optional[Dict[str, Any]] = None,
        json_body: Optional[Dict[str, Any]] = None
    ) -> List[InjectionPoint]:
        """
        Public method.

        Phân loại tham số từ query params và JSON body.

        """
        injection_points: List[InjectionPoint] = []

        if params is None:
            params = {}

        if json_body is None:
            json_body = {}

        if not isinstance(params, dict):
            self.logger.warning("params must be dict. Got: %s", type(params).__name__)
            params = {}

        if not isinstance(json_body, dict):
            self.logger.warning("json_body must be dict. Got: %s", type(json_body).__name__)
            json_body = {}

        query_points = self._classify_dict(
            data=params,
            location="query",
            parent_path="query"
        )

        json_points = self._classify_dict(
            data=json_body,
            location="json",
            parent_path="json"
        )

        injection_points.extend(query_points)
        injection_points.extend(json_points)

        self.logger.info(
            "Parameter classification completed. Injection points found: %s",
            len(injection_points)
        )

        return injection_points

    def _classify_dict(
        self,
        data: Dict[str, Any],
        location: str,
        parent_path: str
    ) -> List[InjectionPoint]:
        """
        Private method.

        Duyệt dict và phân loại từng key-value.
        Hỗ trợ JSON lồng nhau.

        """
        points: List[InjectionPoint] = []

        for key, value in data.items():
            key_as_string = str(key)
            current_path = f"{parent_path}.{key_as_string}"

            if self._is_sensitive_key(key_as_string):
                self.logger.info("Skipping sensitive parameter: %s", current_path)
                continue

            param_type = self._detect_type(value)
            risk_tags = self._build_risk_tags(
                name=key_as_string,
                value=value,
                param_type=param_type
            )

            if param_type == "object" and isinstance(value, dict):
                nested_points = self._classify_dict(
                    data=value,
                    location=location,
                    parent_path=current_path
                )
                points.extend(nested_points)
                continue

            point = InjectionPoint(
                name=key_as_string,
                location=location,
                param_type=param_type,
                original_value=value,
                risk_tags=risk_tags,
                path=current_path
            )

            points.append(point)

        return points

    def _detect_type(self, value: Any) -> str:
        """
        Private method.

        Phân loại kiểu dữ liệu của value.

        :param value: giá trị tham số
        :return: param_type
        """
        if value is None:
            return "null"

        if isinstance(value, bool):
            return "boolean"

        if isinstance(value, int) or isinstance(value, float):
            return "number"

        if isinstance(value, list):
            return "array"

        if isinstance(value, dict):
            return "object"

        if isinstance(value, str):
            stripped_value = value.strip()

            if stripped_value == "":
                return "string"

            if self._looks_like_number(stripped_value):
                return "number"

            if stripped_value.lower() in self.BOOLEAN_LIKE_STRINGS:
                return "boolean"

            return "string"

        return "unknown"

    def _looks_like_number(self, value: str) -> bool:
        """
        Private method.

        Kiểm tra string có giống số không.

        """
        try:
            float(value)
            return True
        except ValueError:
            return False

    def _is_sensitive_key(self, key: str) -> bool:
        """
        Private method.

        Kiểm tra tên tham số có nhạy cảm không.
        """
        normalized_key = key.lower().strip()

        if normalized_key in self.SENSITIVE_KEYWORDS:
            return True

        for keyword in self.SENSITIVE_KEYWORDS:
            if keyword in normalized_key:
                return True

        return False

    def _build_risk_tags(
        self,
        name: str,
        value: Any,
        param_type: str
    ) -> List[str]:
        """
        Private method.

        Gắn risk tag cho InjectionPoint.

        """
        tags: List[str] = []

        normalized_name = name.lower().strip()

        if param_type == "number":
            tags.append("numeric_input")

        if param_type == "string":
            tags.append("string_input")

        if param_type == "boolean":
            tags.append("boolean_input")

        if param_type == "array":
            tags.append("array_input")

        if normalized_name in self.ID_LIKE_KEYWORDS or normalized_name.endswith("_id"):
            tags.append("idor_candidate")
            tags.append("numeric_identifier")

        if "email" in normalized_name:
            tags.append("email_input")

        if "name" in normalized_name:
            tags.append("name_input")

        if "url" in normalized_name or "redirect" in normalized_name:
            tags.append("url_input")
            tags.append("redirect_candidate")

        if "file" in normalized_name or "path" in normalized_name:
            tags.append("path_candidate")

        if "cmd" in normalized_name or "command" in normalized_name:
            tags.append("command_candidate")

        if isinstance(value, str) and len(value) > 100:
            tags.append("long_text_input")

        return list(dict.fromkeys(tags))

    def _setup_logger(self) -> logging.Logger:
        """
        Private method.

        Tạo logger riêng cho ParameterClassifier.
        """
        logger = logging.getLogger("ParameterClassifier")

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
    Test nhanh Phase 6.
    """

    classifier = ParameterClassifier()

    sample_params = {
        "id": "1",
        "name": "admin",
        "page": "2",
        "redirect_url": "http://example.com",
        "csrf_token": "abc-secret-token"
    }

    sample_json_body = {
        "email": "admin@test.com",
        "is_admin": False,
        "password": "123456",
        "profile": {
            "user_id": 10,
            "display_name": "Administrator",
            "avatar_path": "/uploads/a.png"
        }
    }

    injection_points = classifier.classify(
        params=sample_params,
        json_body=sample_json_body
    )

    print("\n Injection Points ")

    for point in injection_points:
        print(point.to_dict())