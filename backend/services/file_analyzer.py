import hashlib
import math
from typing import Dict, Any

from utils.logger import logger


class FileAnalyzer:
    BENIGN_EXTS = {"pdf", "doc", "docx", "xls", "xlsx", "jpg", "jpeg", "png", "txt"}
    DANGEROUS_EXTS = {"exe", "bat", "cmd", "ps1", "sh", "vbs", "jar", "scr", "com"}

    # ========================
    # MAGIC BYTES DETECTION
    # ========================
    @staticmethod
    def _detect_file_type(file_bytes: bytes) -> str:
        if file_bytes.startswith(b"MZ"):
            return "executable"

        if file_bytes.startswith(b"%PDF"):
            return "pdf"

        if file_bytes.startswith(b"\x89PNG"):
            return "image"

        if file_bytes.startswith(b"\xff\xd8"):
            return "image"

        if file_bytes.startswith(b"PK"):
            return "zip"  # docx, xlsx, apk, jar

        return "unknown"

    # ========================
    # ENTROPY (detect packed malware)
    # ========================
    @staticmethod
    def _calculate_entropy(data: bytes) -> float:
        if not data:
            return 0.0

        freq = [0] * 256
        for b in data:
            freq[b] += 1

        entropy = 0.0
        for f in freq:
            if f == 0:
                continue
            p = f / len(data)
            entropy -= p * math.log2(p)

        return entropy

    # ========================
    # DOUBLE EXTENSION
    # ========================
    @staticmethod
    def _has_double_extension(filename: str) -> bool:
        parts = filename.lower().split(".")
        if len(parts) <= 2:
            return False
        second_last_ext = parts[-2]
        last_ext = parts[-1]
        return second_last_ext in FileAnalyzer.BENIGN_EXTS and last_ext in FileAnalyzer.DANGEROUS_EXTS

    # ========================
    # SUSPICIOUS STRINGS
    # ========================
    @staticmethod
    def _scan_strings(file_bytes: bytes) -> Dict[str, bool]:
        lower = file_bytes.lower()

        keywords = [
            b"powershell",
            b"cmd.exe",
            b"wget",
            b"curl",
            b"bash",
            b"sh ",
            b"eval(",
            b"base64",
        ]

        return {k.decode(): (k in lower) for k in keywords}

    # ========================
    # MAIN ANALYSIS
    # ========================
    @classmethod
    def analyze(cls, file_bytes: bytes, filename: str) -> Dict[str, Any]:
        result: Dict[str, Any] = {
            "filename": filename,
            "size": len(file_bytes),
            "sha256": None,
            "detected_type": "unknown",
            "extension": filename.split(".")[-1].lower() if "." in filename else None,
            "entropy": 0.0,
            "double_extension": False,
            "string_flags": {},
            "suspicious": False,
            "risk_flags": [],
        }

        try:
            # ========================
            # HASH
            # ========================
            result["sha256"] = hashlib.sha256(file_bytes).hexdigest()

            # ========================
            # TYPE DETECTION (REAL)
            # ========================
            detected_type = cls._detect_file_type(file_bytes)
            result["detected_type"] = detected_type

            # ========================
            # DOUBLE EXTENSION
            # ========================
            if cls._has_double_extension(filename):
                result["double_extension"] = True
                result["risk_flags"].append("double_extension")

            # ========================
            # ENTROPY
            # ========================
            entropy = cls._calculate_entropy(file_bytes[:50000])  # limit sample
            result["entropy"] = entropy

            if entropy > 7.5:
                result["risk_flags"].append("high_entropy")

            # ========================
            # STRING SCAN
            # ========================
            string_flags = cls._scan_strings(file_bytes[:50000])
            result["string_flags"] = string_flags

            if any(string_flags.values()):
                result["risk_flags"].append("suspicious_strings")

            # ========================
            # TYPE VS EXTENSION MISMATCH
            # ========================
            ext = result["extension"]

            if detected_type == "executable" and ext not in ["exe"]:
                result["risk_flags"].append("fake_extension")

            if detected_type == "zip" and ext in ["docx", "xlsx"]:
                # OK (office files)
                pass
            elif detected_type == "zip" and ext not in ["zip", "docx", "xlsx", "apk"]:
                result["risk_flags"].append("unexpected_zip")

            # ========================
            # EXECUTABLE → HIGH RISK
            # ========================
            if detected_type == "executable":
                result["risk_flags"].append("executable_file")

            # ========================
            # FINAL SUSPICIOUS FLAG
            # ========================
            if result["risk_flags"]:
                result["suspicious"] = True

        except Exception as e:
            logger.warning("file_analysis_failed | %s", str(e))

        return result