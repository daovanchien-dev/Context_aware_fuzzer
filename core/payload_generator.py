"""
Phase 7: Payload Generator

Nhiệm vụ:
- Đọc các file JSON trong thư mục payloads/
- Cung cấp light payload dựa theo param_type
- Cung cấp deep payload dựa theo param_type và vulnerability_family
- Có validate nhẹ để payload file sai không làm tool crash
- Có thể reload payload khi người dùng sửa file

Module này KHÔNG gửi HTTP request.
Module này KHÔNG fuzzing.
Module này KHÔNG phân tích response.
"""

import json
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional


try:
    from parameter_classifier import InjectionPoint
except ImportError:
    try:
        from core.parameter_classifier import InjectionPoint
    except ImportError:
        InjectionPoint = Any


@dataclass
class PayloadItem:
    """
    PayloadItem là object chuẩn cho một payload.

    Fields:
        family:
            Nhóm lỗ hổng, ví dụ:
                - sqli
                - xss
                - path_traversal
                - command_injection
                - idor

        level:
            Mức payload:
                - light
                - deep

        param_type:
            Kiểu tham số:
                - number
                - string
                - boolean
                - array
                - object
                - unknown

        payload:
            Chuỗi payload thực tế.

        source_file:
            File JSON chứa payload này.
    """

    family: str
    level: str
    param_type: str
    payload: str
    source_file: str

    def to_dict(self) -> Dict[str, Any]:
        """
        Convert PayloadItem sang dict.
        """
        return {
            "family": self.family,
            "level": self.level,
            "param_type": self.param_type,
            "payload": self.payload,
            "source_file": self.source_file
        }


class PayloadGeneratorError(Exception):
    """
    Exception riêng cho PayloadGenerator.
    """
    pass


class PayloadGenerator:
    """
    Payload Generator.

    Contract:
    ---------
    Input:
        - payloads/*.json
        - param_type
        - vulnerability_family

    Output:
        - List[PayloadItem]

    Public methods:
        - reload()
        - get_light_payloads(param_type)
        - get_deep_payloads(param_type, vulnerability_family)
        - get_payloads_for_injection_point(injection_point)

    Các module khác KHÔNG gọi private method.
    """

    DEFAULT_PAYLOAD_DIR = Path("payloads")

    SUPPORTED_PARAM_TYPES = {
        "number",
        "string",
        "boolean",
        "null",
        "array",
        "object",
        "unknown"
    }

    DEFAULT_FAMILIES_BY_TAG = {
        "idor_candidate": ["idor"],
        "path_candidate": ["path_traversal"],
        "command_candidate": ["command_injection"],
        "redirect_candidate": ["xss"],
        "string_input": ["sqli", "xss"],
        "numeric_input": ["sqli", "idor"],
        "boolean_input": ["sqli"],
        "url_input": ["xss"],
        "email_input": ["sqli", "xss"],
        "name_input": ["sqli", "xss"]
    }

    def __init__(self, payload_dir: Optional[str] = None):
        """
        Khởi tạo PayloadGenerator.

        :param payload_dir: thư mục chứa payload JSON
        """
        self.logger = self._setup_logger()
        self.payload_dir = Path(payload_dir) if payload_dir else self.DEFAULT_PAYLOAD_DIR

        self.payload_db: Dict[str, Dict[str, Any]] = {}

        self.reload()

    def reload(self) -> None:
        """
        Public method.

        Load lại toàn bộ payload JSON từ thư mục payloads/.

        :return: None
        """
        self.payload_db = {}

        if not self.payload_dir.exists():
            self.logger.warning("Payload directory does not exist: %s", self.payload_dir)
            return

        if not self.payload_dir.is_dir():
            self.logger.warning("Payload path is not a directory: %s", self.payload_dir)
            return

        json_files = sorted(self.payload_dir.glob("*.json"))

        if not json_files:
            self.logger.warning("No payload JSON files found in: %s", self.payload_dir)
            return

        for file_path in json_files:
            self._load_payload_file(file_path)

        self.logger.info(
            "Payload loading completed. Families loaded: %s",
            list(self.payload_db.keys())
        )

    def get_light_payloads(self, param_type: str) -> List[PayloadItem]:
        """
        Public method.

        Lấy toàn bộ light payload phù hợp với param_type từ tất cả family.

        :param param_type: number/string/boolean/...
        :return: List[PayloadItem]
        """
        normalized_type = self._normalize_param_type(param_type)

        payload_items: List[PayloadItem] = []

        for family, payload_data in self.payload_db.items():
            light_payloads = payload_data.get("light_payloads", {})

            values = self._get_payload_values_by_type(
                payload_map=light_payloads,
                param_type=normalized_type
            )

            for payload in values:
                payload_items.append(
                    PayloadItem(
                        family=family,
                        level="light",
                        param_type=normalized_type,
                        payload=payload,
                        source_file=payload_data.get("_source_file", "")
                    )
                )

        return self._deduplicate_payload_items(payload_items)

    def get_deep_payloads(
        self,
        param_type: str,
        vulnerability_family: str
    ) -> List[PayloadItem]:
        """
        Public method.

        Lấy deep payload theo param_type và vulnerability_family.

        :param param_type: number/string/boolean/...
        :param vulnerability_family: sqli/xss/path_traversal/...
        :return: List[PayloadItem]
        """
        normalized_type = self._normalize_param_type(param_type)
        family = self._normalize_family(vulnerability_family)

        payload_data = self.payload_db.get(family)

        if not payload_data:
            self.logger.warning("Payload family not found: %s", family)
            return []

        deep_payloads = payload_data.get("deep_payloads", {})

        values = self._get_payload_values_by_type(
            payload_map=deep_payloads,
            param_type=normalized_type
        )

        payload_items = [
            PayloadItem(
                family=family,
                level="deep",
                param_type=normalized_type,
                payload=payload,
                source_file=payload_data.get("_source_file", "")
            )
            for payload in values
        ]

        return self._deduplicate_payload_items(payload_items)

    def get_payloads_for_injection_point(
        self,
        injection_point: InjectionPoint
    ) -> List[PayloadItem]:
        """
        Public method.

        Sinh light payload phù hợp với một InjectionPoint.

        Logic:
        - Dựa vào param_type để lấy light payload chung.
        - Dựa vào risk_tags để ưu tiên family phù hợp.
        - Nếu không có risk_tags phù hợp thì trả light payload theo param_type từ tất cả family.

        :param injection_point: InjectionPoint từ Phase 6
        :return: List[PayloadItem]
        """
        param_type = getattr(injection_point, "param_type", "unknown")
        risk_tags = getattr(injection_point, "risk_tags", [])

        normalized_type = self._normalize_param_type(param_type)

        preferred_families = self._families_from_risk_tags(risk_tags)

        if not preferred_families:
            return self.get_light_payloads(normalized_type)

        payload_items: List[PayloadItem] = []

        for family in preferred_families:
            payload_data = self.payload_db.get(family)

            if not payload_data:
                continue

            light_payloads = payload_data.get("light_payloads", {})

            values = self._get_payload_values_by_type(
                payload_map=light_payloads,
                param_type=normalized_type
            )

            for payload in values:
                payload_items.append(
                    PayloadItem(
                        family=family,
                        level="light",
                        param_type=normalized_type,
                        payload=payload,
                        source_file=payload_data.get("_source_file", "")
                    )
                )

        if not payload_items:
            payload_items = self.get_light_payloads(normalized_type)

        return self._deduplicate_payload_items(payload_items)

    def _load_payload_file(self, file_path: Path) -> None:
        """
        Private method.

        Load một file payload JSON.
        Nếu file rỗng hoặc JSON lỗi thì warning, không crash.
        """
        try:
            if file_path.stat().st_size == 0:
                self.logger.warning("Skipping empty payload file: %s", file_path)
                return

            with file_path.open("r", encoding="utf-8") as file:
                data = json.load(file)

            if not isinstance(data, dict):
                self.logger.warning("Skipping payload file with non-object root: %s", file_path)
                return

            family = data.get("family")

            if not family or not isinstance(family, str):
                family = file_path.stem

            family = self._normalize_family(family)

            if not self._is_valid_payload_data(data):
                self.logger.warning("Payload file has invalid structure: %s", file_path)
                return

            data["_source_file"] = str(file_path)

            self.payload_db[family] = data

            self.logger.info("Loaded payload family '%s' from %s", family, file_path)

        except json.JSONDecodeError as error:
            self.logger.warning("Invalid JSON in payload file %s: %s", file_path, error)

        except OSError as error:
            self.logger.warning("Cannot read payload file %s: %s", file_path, error)

        except Exception as error:
            self.logger.exception("Unexpected error while loading payload file %s: %s", file_path, error)

    def _is_valid_payload_data(self, data: Dict[str, Any]) -> bool:
        """
        Private method.

        Validate nhẹ cấu trúc payload.

        Chấp nhận file có ít nhất một trong:
            - light_payloads
            - deep_payloads
        """
        has_light = "light_payloads" in data
        has_deep = "deep_payloads" in data

        if not has_light and not has_deep:
            return False

        if has_light and not isinstance(data.get("light_payloads"), dict):
            return False

        if has_deep and not isinstance(data.get("deep_payloads"), dict):
            return False

        return True

    def _get_payload_values_by_type(
        self,
        payload_map: Dict[str, Any],
        param_type: str
    ) -> List[str]:
        """
        Private method.

        Lấy payload theo param_type.

        Ưu tiên:
            1. payload_map[param_type]
            2. payload_map["string"] nếu param_type không có
            3. payload_map["unknown"] nếu có
            4. [] nếu không có gì
        """
        if not isinstance(payload_map, dict):
            return []

        candidate_values = []

        if param_type in payload_map:
            candidate_values = payload_map.get(param_type, [])

        elif "string" in payload_map:
            candidate_values = payload_map.get("string", [])

        elif "unknown" in payload_map:
            candidate_values = payload_map.get("unknown", [])

        if isinstance(candidate_values, str):
            return [candidate_values]

        if isinstance(candidate_values, list):
            return [
                str(payload)
                for payload in candidate_values
                if payload is not None
            ]

        return []

    def _families_from_risk_tags(self, risk_tags: List[str]) -> List[str]:
        """
        Private method.

        Chuyển risk_tags từ Phase 6 thành danh sách vulnerability family ưu tiên.
        """
        families: List[str] = []

        if not isinstance(risk_tags, list):
            return families

        for tag in risk_tags:
            mapped_families = self.DEFAULT_FAMILIES_BY_TAG.get(tag, [])

            for family in mapped_families:
                normalized_family = self._normalize_family(family)

                if normalized_family not in families:
                    families.append(normalized_family)

        return families

    def _normalize_param_type(self, param_type: str) -> str:
        """
        Private method.

        Chuẩn hóa param_type.
        """
        if not isinstance(param_type, str):
            return "unknown"

        normalized = param_type.strip().lower()

        if normalized not in self.SUPPORTED_PARAM_TYPES:
            return "unknown"

        return normalized

    def _normalize_family(self, family: str) -> str:
        """
        Private method.

        Chuẩn hóa family name.
        """
        if not isinstance(family, str):
            return "unknown"

        return family.strip().lower().replace("-", "_").replace(" ", "_")

    def _deduplicate_payload_items(
        self,
        payload_items: List[PayloadItem]
    ) -> List[PayloadItem]:
        """
        Private method.

        Loại bỏ payload trùng nhau.
        """
        seen = set()
        unique_items: List[PayloadItem] = []

        for item in payload_items:
            key = (
                item.family,
                item.level,
                item.param_type,
                item.payload
            )

            if key in seen:
                continue

            seen.add(key)
            unique_items.append(item)

        return unique_items

    def _setup_logger(self) -> logging.Logger:
        """
        Private method.

        Tạo logger riêng cho PayloadGenerator.
        """
        logger = logging.getLogger("PayloadGenerator")

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
    Test nhanh Phase 7.

    Chạy:
        python core/payload_generator.py
    """

    generator = PayloadGenerator()

    print("\n===== Light Payloads for number =====")
    for item in generator.get_light_payloads("number"):
        print(item.to_dict())

    print("\n===== Light Payloads for string =====")
    for item in generator.get_light_payloads("string"):
        print(item.to_dict())

    print("\n===== Deep Payloads for SQLi / string =====")
    for item in generator.get_deep_payloads("string", "sqli"):
        print(item.to_dict())

    print("\n===== Payloads for sample InjectionPoint =====")

    try:
        sample_point = InjectionPoint(
            name="id",
            location="query",
            param_type="number",
            original_value="1",
            risk_tags=["numeric_input", "idor_candidate"],
            path="query.id"
        )

        for item in generator.get_payloads_for_injection_point(sample_point):
            print(item.to_dict())

    except Exception as error:
        print("Cannot create sample InjectionPoint:", error)