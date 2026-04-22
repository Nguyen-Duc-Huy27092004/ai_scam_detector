"""
Web content extraction service (PRODUCTION READY)

- Safe HTTP fetching
- Robust HTML parsing
- Anti-crash guards
- Consistent metadata output
"""

from typing import Tuple, Optional, Dict
from urllib.parse import urlparse, urljoin

from services.async_crawler import SecureCrawler
from utils.logger import logger
from utils.config import USER_AGENT, CONTENT_EXTRACTION_TIMEOUT

try:
    import requests
    from bs4 import BeautifulSoup
    WEB_AVAILABLE = True
except ImportError:
    WEB_AVAILABLE = False
    logger.warning("requests/beautifulsoup_not_available")


# ==========================
# DOMAIN HELPERS
# ==========================

def clean_domain(domain: str) -> str:
    return domain.split(":")[0].lower() if domain else ""


def is_same_root_domain(d1: str, d2: str) -> bool:
    d1 = clean_domain(d1)
    d2 = clean_domain(d2)
    return d1 == d2 or d1.endswith("." + d2)


# ==========================
# MAIN CLASS
# ==========================

class ContentExtractor:

    MAX_HTML_SIZE = 2_000_000
    MAX_TEXT_LENGTH = 5000
    MAX_BUTTON_TEXTS = 30

    UNWANTED_TAGS = [
        "script", "style", "meta", "link", "noscript", "iframe"
    ]

    # ==========================
    # FETCH HTML (HARDENED)
    # ==========================

    @staticmethod
    def extract_from_url(url: str) -> Tuple[Optional[str], Optional[str]]:

        if not WEB_AVAILABLE:
            logger.warning("web_tools_not_available")
            return None, None
        if not SecureCrawler.is_safe_url(url):
            logger.warning("ssrf_blocked_extractor | url=%s", url[:80])
            return None, None

        try:
            headers = {
                "User-Agent": USER_AGENT,
                "Accept": "text/html,application/xhtml+xml",
                "Accept-Language": "en-US,en;q=0.9",
                "Connection": "close",
            }

            response = requests.get(
                url,
                headers=headers,
                timeout=CONTENT_EXTRACTION_TIMEOUT,
                allow_redirects=True,
                verify=True,
            )

            if response.status_code != 200:
                logger.warning("http_error | url=%s | status=%s", url[:80], response.status_code)
                return None, None

            content_type = response.headers.get("Content-Type", "")
            if "text/html" not in content_type:
                logger.warning("non_html_content | url=%s | type=%s", url[:80], content_type)
                return None, None

            html_content = response.text[:ContentExtractor.MAX_HTML_SIZE]

            soup = BeautifulSoup(html_content, "html.parser")

            for tag in ContentExtractor.UNWANTED_TAGS:
                for el in soup.find_all(tag):
                    el.decompose()

            text_content = soup.get_text(separator=" ", strip=True)
            text_content = " ".join(text_content.split())[:ContentExtractor.MAX_TEXT_LENGTH]

            logger.info(
                "content_extracted | url=%s | html=%d | text=%d",
                url[:80],
                len(html_content),
                len(text_content),
            )

            return html_content, text_content

        except requests.exceptions.Timeout:
            logger.warning("content_timeout | url=%s", url[:80])
        except requests.exceptions.SSLError:
            logger.warning("ssl_error | url=%s", url[:80])
        except Exception as e:
            logger.error("content_extraction_failed | url=%s | error=%s", url[:80], str(e))

        return None, None

    # ==========================
    # METADATA EXTRACTION (SAFE)
    # ==========================

    @staticmethod
    def extract_metadata(html_content: str, base_url: str = "") -> Dict:

        try:
            if not html_content:
                return {}

            soup = BeautifulSoup(html_content, "html.parser")
            base_domain = clean_domain(urlparse(base_url).netloc) if base_url else ""

            metadata = {
                "title": None,
                "description": None,
                "lang": None,

                "links_count": 0,
                "images_count": 0,
                "forms_count": 0,

                "password_inputs": 0,
                "hidden_inputs": 0,

                "external_links": 0,
                "iframe_count": 0,

                "has_login_form": False,
                "has_external_form": False,
                "suspicious_forms": [],

                "has_otp_field": False,
                "has_phone_field": False,
                "has_email_field": False,
                "urgency_phrases": [],
                "suspicious_keywords": [],
                "button_texts": [],
            }

            # ======================
            # BASIC META
            # ======================

            if soup.title:
                metadata["title"] = soup.title.get_text(strip=True)

            desc = soup.find("meta", attrs={"name": "description"})
            if desc:
                metadata["description"] = desc.get("content")

            html_tag = soup.find("html")
            if html_tag:
                metadata["lang"] = html_tag.get("lang")

            metadata["links_count"] = len(soup.find_all("a"))
            metadata["images_count"] = len(soup.find_all("img"))
            metadata["iframe_count"] = len(soup.find_all("iframe"))

            # ======================
            # LINKS
            # ======================

            for link in soup.find_all("a"):
                href = link.get("href")
                if not href:
                    continue

                try:
                    full_url = urljoin(base_url, href)
                    domain = clean_domain(urlparse(full_url).netloc)

                    if domain and base_domain and not is_same_root_domain(domain, base_domain):
                        metadata["external_links"] += 1
                except Exception:
                    continue

            # ======================
            # INPUTS
            # ======================

            for input_tag in soup.find_all("input"):
                t = (input_tag.get("type") or "").lower()
                placeholder = (input_tag.get("placeholder") or "").lower()
                name = (input_tag.get("name") or "").lower()

                combined = placeholder + name

                if t == "password":
                    metadata["password_inputs"] += 1

                if t == "hidden":
                    metadata["hidden_inputs"] += 1

                if any(x in combined for x in ["otp", "code", "mã"]):
                    metadata["has_otp_field"] = True

                if t == "tel" or any(x in combined for x in ["phone", "điện thoại"]):
                    metadata["has_phone_field"] = True

                if t == "email" or "email" in combined:
                    metadata["has_email_field"] = True

            # ======================
            # FORMS
            # ======================

            forms = soup.find_all("form")
            metadata["forms_count"] = len(forms)

            for form in forms:
                try:
                    action = form.get("action") or ""
                    inputs = form.find_all("input")

                    has_password = any(
                        (i.get("type") or "").lower() == "password"
                        for i in inputs
                    )

                    full_action = urljoin(base_url, action)
                    action_domain = clean_domain(urlparse(full_action).netloc)

                    is_external = (
                        action_domain and base_domain and
                        not is_same_root_domain(action_domain, base_domain)
                    )

                    if has_password:
                        metadata["has_login_form"] = True

                    if is_external:
                        metadata["has_external_form"] = True

                    if has_password and is_external:
                        metadata["suspicious_forms"].append({
                            "action": full_action,
                            "reason": "password + external submit"
                        })

                except Exception:
                    continue

            # ======================
            # TEXT ANALYSIS
            # ======================

            body_text = soup.get_text(" ", strip=True).lower()

            urgency_keywords = [
                "urgent", "cấp tốc", "ngay lập tức", "immediately",
                "expire", "limited time", "verify now"
            ]

            suspicious_keywords = [
                "verify account", "confirm identity",
                "update information", "click here"
            ]

            for kw in urgency_keywords:
                if kw in body_text:
                    metadata["urgency_phrases"].append(kw)

            for kw in suspicious_keywords:
                if kw in body_text:
                    metadata["suspicious_keywords"].append(kw)

            # Buttons
            for btn in soup.find_all(["button", "a"]):
                if len(metadata["button_texts"]) >= ContentExtractor.MAX_BUTTON_TEXTS:
                    break
                txt = (btn.get_text(strip=True) or "").lower()
                if txt and len(txt) < 100:
                    metadata["button_texts"].append(txt)

            return metadata

        except Exception as e:
            logger.error("metadata_extraction_failed | %s", str(e))
            return {}


# ==========================
# WRAPPERS
# ==========================

def extract_from_url(url: str) -> Tuple[Optional[str], Optional[str]]:
    return ContentExtractor.extract_from_url(url)


def extract_metadata(html_content: str, base_url: str = "") -> Dict:
    return ContentExtractor.extract_metadata(html_content, base_url)