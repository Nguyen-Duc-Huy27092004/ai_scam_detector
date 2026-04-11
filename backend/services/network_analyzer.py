import socket
import ssl
import ipaddress
import datetime
from typing import Dict, Any, List
from urllib.parse import urlparse

from utils.logger import logger


class NetworkAnalyzer:
    TIMEOUT = 3

    # ========================
    # IP VALIDATION
    # ========================
    @staticmethod
    def _is_safe_ip(ip: str) -> bool:
        try:
            ip_obj = ipaddress.ip_address(ip)
            return ip_obj.is_global
        except Exception:
            return False

    # ========================
    # DNS RESOLUTION
    # ========================
    @staticmethod
    def _resolve_all(hostname: str) -> List[str]:
        try:
            infos = socket.getaddrinfo(hostname, None)
            return list(set(i[4][0] for i in infos))
        except Exception:
            return []

    # ========================
    # PORT CHECK
    # ========================
    @staticmethod
    def _check_port(ip: str, port: int) -> bool:
        try:
            with socket.create_connection((ip, port), timeout=2):
                return True
        except Exception:
            return False

    # ========================
    # SSL INSPECTION (IMPROVED)
    # ========================
    @staticmethod
    def _inspect_ssl(hostname: str, port: int) -> Dict[str, Any]:
        result = {
            "valid": False,
            "issuer": None,
            "subject": None,
            "expired": None,
            "days_left": None,
        }

        try:
            context = ssl.create_default_context()

            with socket.create_connection((hostname, port), timeout=3) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()

                    if not cert:
                        return result

                    result["valid"] = True
                    result["issuer"] = dict(x[0] for x in cert.get("issuer", []))
                    result["subject"] = dict(x[0] for x in cert.get("subject", []))

                    # parse expiration
                    not_after = cert.get("notAfter")
                    if not_after:
                        expire_date = datetime.datetime.strptime(
                            not_after, "%b %d %H:%M:%S %Y %Z"
                        )
                        now = datetime.datetime.utcnow()
                        delta = (expire_date - now).days

                        result["expired"] = delta < 0
                        result["days_left"] = delta

        except Exception as e:
            logger.debug("ssl_inspect_fail | %s", str(e))

        return result

    # ========================
    # BASIC GEO + ASN (mockable)
    # ========================
    @staticmethod
    def _basic_ip_intel(ip: str) -> Dict[str, Any]:
        """
        NOTE: Production nên dùng:
        - ipinfo.io
        - ip-api.com
        - MaxMind GeoIP
        """
        intel = {
            "is_datacenter": False,
            "country": None,
            "org": None,
        }

        # Heuristic đơn giản
        if ip.startswith(("34.", "35.", "52.", "54.")):
            intel["is_datacenter"] = True
            intel["org"] = "AWS"

        if ip.startswith(("104.", "172.")):
            intel["is_datacenter"] = True
            intel["org"] = "Cloudflare"

        return intel

    # ========================
    # MAIN
    # ========================
    @classmethod
    def analyze(cls, url: str) -> Dict[str, Any]:
        result: Dict[str, Any] = {
            "hostname": None,
            "ips": [],
            "safe_ips": [],
            "port": None,
            "port_open": False,
            "ssl": {},
            "intel": {},
            "risk_flags": [],
            "errors": [],
        }

        try:
            parsed = urlparse(url)
            hostname = parsed.hostname
            port = parsed.port or (443 if parsed.scheme == "https" else 80)

            if not hostname:
                return result

            result["hostname"] = hostname
            result["port"] = port

            # DNS
            ips = cls._resolve_all(hostname)
            result["ips"] = ips

            safe_ips = [ip for ip in ips if cls._is_safe_ip(ip)]
            result["safe_ips"] = safe_ips

            if not safe_ips:
                result["risk_flags"].append("no_safe_ip")
                return result

            ip = safe_ips[0]

            # PORT
            result["port_open"] = cls._check_port(ip, port)
            if not result["port_open"]:
                result["risk_flags"].append("port_closed")

            # SSL
            if parsed.scheme == "https":
                ssl_data = cls._inspect_ssl(hostname, port)
                result["ssl"] = ssl_data

                if not ssl_data.get("valid"):
                    result["risk_flags"].append("invalid_ssl")

                if ssl_data.get("expired"):
                    result["risk_flags"].append("expired_ssl")

                if ssl_data.get("days_left") is not None and ssl_data["days_left"] < 7:
                    result["risk_flags"].append("ssl_expiring_soon")

            # INTEL
            intel = cls._basic_ip_intel(ip)
            result["intel"] = intel

            if intel.get("is_datacenter"):
                result["risk_flags"].append("datacenter_ip")

            # BEHAVIOR
            if len(ips) > 5:
                result["risk_flags"].append("many_ips")

        except Exception as e:
            logger.warning("network_analyze_failed | %s", str(e))
            result["errors"].append(str(e))

        return result