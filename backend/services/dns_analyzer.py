"""
DNS Analyzer.

Fixes applied:
  L1 — Trusted domain bypass: replaced substring `in` check with exact
       suffix matching so `evil-google.com` is NOT treated as trusted.
  L3 — Bare `except: pass` blocks replaced with `except Exception as e`
       with debug-level logging for better production visibility.
"""

from typing import Optional
from urllib.parse import urlparse
from utils.logger import logger

try:
    import dns.resolver
    import dns.exception
    DNSPYTHON_AVAILABLE = True
except ImportError:
    DNSPYTHON_AVAILABLE = False
    logger.warning("dnspython_not_installed | dns_analysis_disabled")


TRUSTED_DOMAINS = [
    "google.com",
    "youtube.com",
    "facebook.com",
    "microsoft.com",
    "apple.com",
]


def _is_trusted(domain: str) -> bool:
    """
    L1: Exact suffix check so that `evil-google.com` does NOT match
    `google.com`. Previously `any(td in domain ...)` would match substrings.
    """
    domain = domain.lower()
    for td in TRUSTED_DOMAINS:
        if domain == td or domain.endswith("." + td):
            return True
    return False


def extract_domain(url: str) -> str:
    try:
        parsed = urlparse(url if "://" in url else f"http://{url}")
        domain = parsed.netloc or parsed.path
        return domain.split(":")[0].lower()
    except Exception:
        return ""


def analyze_dns(url: str) -> dict:
    result = {
        "has_mx":            False,
        "has_spf":           False,
        "has_dmarc":         False,
        "nameservers":       [],
        "a_records":         [],
        "mx_records":        [],
        "txt_records":       [],
        "suspicious_signals": [],
        "error":             None,
    }

    if not DNSPYTHON_AVAILABLE:
        result["error"] = "dnspython not installed"
        return result

    domain = extract_domain(url)
    if not domain:
        result["error"] = "invalid domain"
        return result

    # L1: Use suffix-safe trusted domain check
    if _is_trusted(domain):
        logger.info("trusted_domain_skip_dns | domain=%s", domain)
        return result

    resolver = dns.resolver.Resolver()
    resolver.lifetime = 5.0

    # A record
    try:
        answers = resolver.resolve(domain, "A")
        result["a_records"] = [str(r) for r in answers]
    except dns.resolver.NXDOMAIN:
        result["suspicious_signals"].append("domain_not_exist")
        return result
    except dns.exception.Timeout:
        result["error"] = "dns_timeout"
        return result
    except Exception as e:
        # L3: Log instead of silently swallowing
        logger.debug("dns_a_record_failed | domain=%s | error=%s", domain, str(e))

    # NS record
    try:
        answers = resolver.resolve(domain, "NS")
        result["nameservers"] = [str(r).rstrip(".") for r in answers]
    except Exception as e:
        logger.debug("dns_ns_record_failed | domain=%s | error=%s", domain, str(e))

    # MX record
    try:
        answers = resolver.resolve(domain, "MX")
        result["mx_records"] = [str(r.exchange).rstrip(".") for r in answers]
        result["has_mx"] = len(result["mx_records"]) > 0
    except dns.resolver.NoAnswer:
        pass
    except Exception as e:
        logger.debug("dns_mx_record_failed | domain=%s | error=%s", domain, str(e))

    # TXT record / SPF
    try:
        answers = resolver.resolve(domain, "TXT")
        for r in answers:
            txt = r.to_text().strip('"')
            result["txt_records"].append(txt)
            if txt.lower().startswith("v=spf1"):
                result["has_spf"] = True
    except Exception as e:
        logger.debug("dns_txt_record_failed | domain=%s | error=%s", domain, str(e))

    # DMARC
    try:
        answers = resolver.resolve(f"_dmarc.{domain}", "TXT")
        for r in answers:
            if "v=dmarc1" in r.to_text().lower():
                result["has_dmarc"] = True
    except Exception as e:
        logger.debug("dns_dmarc_failed | domain=%s | error=%s", domain, str(e))

    # Suspicious signal detection
    if not result["a_records"]:
        result["suspicious_signals"].append("no_a_record")

    if not result["nameservers"]:
        result["suspicious_signals"].append("no_nameservers")

    if not result["has_spf"]:
        logger.debug("dns_no_spf | domain=%s", domain)

    if not result["has_dmarc"]:
        logger.debug("dns_no_dmarc | domain=%s", domain)

    # Suspicious nameservers
    _SUSPICIOUS_NS = ["freenom", "afraid.org", "no-ip"]
    for ns in result["nameservers"]:
        if any(s in ns.lower() for s in _SUSPICIOUS_NS):
            result["suspicious_signals"].append(f"suspicious_nameserver:{ns}")

    return result