"""
Domain intelligence module.
Collect WHOIS, SSL, DNS, and heuristic signals for scam detection.
"""

import socket
import ssl
import re
from datetime import datetime
from urllib.parse import urlparse
from typing import Dict, Any

import whois
from utils.logger import logger


SUSPICIOUS_TLDS = {
    "tk", "ml", "ga", "cf", "xyz", "top", "win", "click", "review", "vip"
}

SUSPICIOUS_KEYWORDS = {
    "login", "verify", "secure", "account", "update",
    "bank", "paypal", "apple", "google", "facebook",
    "confirm", "support", "service", "wallet"
}


def get_domain_intel(url: str) -> Dict[str, Any]:
    parsed = urlparse(url)
    domain = parsed.netloc.split(":")[0]

    result = {
        "domain": domain,
        "is_https": url.startswith("https://"),
        "is_ip": False,
        "age_days": None,
        "subdomain_count": 0,
        "tld": None,
        "whois_registered": False,
        "ssl_valid": False,
        "suspicious_patterns": []
    }

    try:
        # ================= IP check =================
        if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", domain):
            result["is_ip"] = True
            result["suspicious_patterns"].append("ip_address")

        # ================= Subdomain =================
        parts = domain.split(".")
        result["subdomain_count"] = len(parts) - 2 if len(parts) > 2 else 0

        # ================= TLD =================
        tld = parts[-1].lower()
        result["tld"] = tld
        if tld in SUSPICIOUS_TLDS:
            result["suspicious_patterns"].append("suspicious_tld")

        # ================= Keyword =================
        domain_lower = domain.lower()
        for kw in SUSPICIOUS_KEYWORDS:
            if kw in domain_lower:
                result["suspicious_patterns"].append(f"keyword_{kw}")

        # ================= WHOIS =================
        try:
            whois_info = whois.whois(domain)
            creation_date = whois_info.creation_date

            if isinstance(creation_date, list):
                creation_date = creation_date[0]

            if creation_date:
                age_days = (datetime.utcnow() - creation_date).days
                result["age_days"] = age_days
                result["whois_registered"] = True

                if age_days < 30:
                    result["suspicious_patterns"].append("new_domain")
                elif age_days < 90:
                    result["suspicious_patterns"].append("young_domain")
            else:
                result["suspicious_patterns"].append("no_creation_date")

        except Exception as e:
            logger.warning("whois_failed | %s | %s", domain, str(e))
            result["suspicious_patterns"].append("whois_failed")

        # ================= SSL =================
        if result["is_https"]:
            try:
                context = ssl.create_default_context()
                with socket.create_connection((domain, 443), timeout=5) as sock:
                    with context.wrap_socket(sock, server_hostname=domain) as ssock:
                        cert = ssock.getpeercert()
                        if cert:
                            result["ssl_valid"] = True
            except Exception as e:
                logger.warning("ssl_failed | %s | %s", domain, str(e))
                result["suspicious_patterns"].append("invalid_ssl")
        else:
            result["suspicious_patterns"].append("no_https")

        # ================= Subdomain abuse =================
        if result["subdomain_count"] >= 3:
            result["suspicious_patterns"].append("too_many_subdomains")

        logger.info("domain_intel_done | %s", domain)
        return result

    except Exception as e:
        logger.error("domain_intel_failed | %s | %s", domain, str(e))
        result["error"] = str(e)
        return result