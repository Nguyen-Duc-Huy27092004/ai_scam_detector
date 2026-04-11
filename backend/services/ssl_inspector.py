"""
SSL Certificate Inspector.

Fixes applied:
  L4 — Removed "let's encrypt" from _LOW_TRUST_ISSUERS.
       Let's Encrypt is used by the vast majority of legitimate HTTPS sites
       and flagging it produces a high false-positive rate. Free CAs that are
       genuinely associated with phishing infrastructure (ZeroSSL, Buypass)
       are retained in the list.
"""

import ssl
import socket
from datetime import datetime, timezone
from urllib.parse import urlparse
from typing import Optional
from utils.logger import logger


# L4: Removed "let's encrypt" — it is the most widely used CA for legitimate
# sites. Retaining ZeroSSL and Buypass which have a much higher phishing ratio.
_LOW_TRUST_ISSUERS = {
    "zerossl",
    "buypass",
    "sectigo",
}

# CAs strongly associated with legitimate organizations
_HIGH_TRUST_ISSUERS = {
    "digicert", "globalsign", "comodo", "entrust", "verisign",
    "quovadis", "trustwave", "geotrust", "thawte",
}


def inspect_ssl(url: str) -> dict:
    """
    Inspect the SSL certificate of a URL.

    Returns:
        dict with keys:
            has_ssl, is_valid, is_self_signed, is_expired,
            days_until_expiry, issuer, subject, not_before, not_after,
            issuer_trust ('high' | 'low' | 'unknown'),
            suspicious_signals (list[str]),
            error (str | None)
    """
    result = {
        "has_ssl":           False,
        "is_valid":          False,
        "is_self_signed":    False,
        "is_expired":        False,
        "days_until_expiry": None,
        "issuer":            None,
        "subject":           None,
        "not_before":        None,
        "not_after":         None,
        "issuer_trust":      "unknown",
        "suspicious_signals": [],
        "error":             None,
    }

    try:
        parsed   = urlparse(url)
        hostname = parsed.hostname
        port     = parsed.port or 443

        if not hostname:
            result["error"] = "No hostname"
            return result

        if parsed.scheme != "https":
            result["has_ssl"] = False
            result["suspicious_signals"].append("no_https")
            return result

        # ── Primary: verified TLS handshake ──────────────────────────────────
        context = ssl.create_default_context()
        context.check_hostname = True
        context.verify_mode    = ssl.CERT_REQUIRED

        cert = None
        try:
            with socket.create_connection((hostname, port), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as tls_sock:
                    cert = tls_sock.getpeercert()
                    result["has_ssl"]  = True
                    result["is_valid"] = True

        except ssl.SSLCertVerificationError as e:
            result["has_ssl"]  = True
            result["is_valid"] = False
            result["suspicious_signals"].append("ssl_verification_failed")
            result["error"] = str(e)

            # ── Fallback: read cert data without verification ─────────────────
            # Store in a separate variable to avoid overwriting verified data.
            unverified_cert = None
            ctx_noverify = ssl.create_default_context()
            ctx_noverify.check_hostname = False
            ctx_noverify.verify_mode    = ssl.CERT_NONE
            try:
                with socket.create_connection((hostname, port), timeout=5) as sock:
                    with ctx_noverify.wrap_socket(
                        sock, server_hostname=hostname
                    ) as tls_sock:
                        unverified_cert = tls_sock.getpeercert()
            except Exception as inner_e:
                logger.debug("ssl_fallback_read_failed | host=%s | %s", hostname, str(inner_e))
                return result

            cert = unverified_cert  # only used for metadata parsing below

        except (socket.timeout, ConnectionRefusedError, OSError) as e:
            result["has_ssl"] = False
            result["suspicious_signals"].append("ssl_connection_failed")
            result["error"] = f"Connection failed: {type(e).__name__}"
            return result

        if not cert:
            result["error"] = "Empty certificate"
            return result

        # ── Parse Subject ─────────────────────────────────────────────────────
        subject_dict = dict(x[0] for x in cert.get("subject", []))
        result["subject"] = subject_dict.get("commonName", "")

        # ── Parse Issuer ──────────────────────────────────────────────────────
        issuer_dict  = dict(x[0] for x in cert.get("issuer", []))
        issuer_org   = issuer_dict.get("organizationName", "")
        issuer_cn    = issuer_dict.get("commonName", "")
        result["issuer"] = issuer_org or issuer_cn

        # Self-signed: issuer == subject
        subject_org = subject_dict.get("organizationName", "")
        if (
            (issuer_cn  and issuer_cn  == subject_dict.get("commonName", ""))
            or (issuer_org and issuer_org == subject_org)
        ):
            result["is_self_signed"] = True
            result["suspicious_signals"].append("self_signed_certificate")

        # ── Parse Dates ───────────────────────────────────────────────────────
        now = datetime.now(tz=timezone.utc)

        not_after_str = cert.get("notAfter", "")
        if not_after_str:
            try:
                not_after = datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z")
                not_after = not_after.replace(tzinfo=timezone.utc)
                result["not_after"] = not_after.isoformat()

                days_until = (not_after - now).days
                result["days_until_expiry"] = days_until

                if days_until < 0:
                    result["is_expired"] = True
                    result["is_valid"]   = False
                    result["suspicious_signals"].append("certificate_expired")
                elif days_until < 30:
                    result["suspicious_signals"].append("certificate_expiring_soon")
            except ValueError:
                pass

        not_before_str = cert.get("notBefore", "")
        if not_before_str:
            try:
                not_before = datetime.strptime(not_before_str, "%b %d %H:%M:%S %Y %Z")
                result["not_before"] = not_before.replace(tzinfo=timezone.utc).isoformat()
            except ValueError:
                pass

        # ── Issuer trust level ────────────────────────────────────────────────
        issuer_lower = result["issuer"].lower() if result["issuer"] else ""
        if any(t in issuer_lower for t in _HIGH_TRUST_ISSUERS):
            result["issuer_trust"] = "high"
        elif any(t in issuer_lower for t in _LOW_TRUST_ISSUERS):
            result["issuer_trust"] = "low"
            result["suspicious_signals"].append("low_trust_issuer")
        else:
            result["issuer_trust"] = "unknown"

        logger.info(
            "ssl_inspection_complete | host=%s | valid=%s | days_left=%s | issuer=%s",
            hostname, result["is_valid"], result["days_until_expiry"], result["issuer"],
        )

    except Exception as e:
        result["error"] = f"SSL inspection error: {type(e).__name__}"
        result["suspicious_signals"].append("ssl_inspection_error")
        logger.warning("ssl_inspection_failed | url=%s | error=%s", url[:80], str(e))

    return result
