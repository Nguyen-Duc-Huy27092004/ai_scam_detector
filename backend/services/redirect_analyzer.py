import requests
import socket
import time
from typing import Dict, Any, List
from urllib.parse import urljoin
from requests.exceptions import Timeout, ConnectionError, RequestException
from services.async_crawler import SecureCrawler
from utils.logger import logger


MAX_REDIRECTS = 5
TIMEOUT = 10
MAX_RETRIES = 2
INITIAL_BACKOFF = 1  # seconds

_DEFAULT_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
}


def _fetch_with_retry(url: str, max_retries: int = MAX_RETRIES) -> requests.Response | None:
    """
    Fetch URL with retry logic for transient DNS/network failures.
    
    Args:
        url: URL to fetch
        max_retries: Maximum number of retry attempts
        
    Returns:
        Response object or None if all retries failed
    """
    backoff = INITIAL_BACKOFF
    
    for attempt in range(max_retries + 1):
        try:
            response = requests.get(
                url,
                headers=_DEFAULT_HEADERS,
                timeout=TIMEOUT,
                allow_redirects=False
            )
            return response
            
        except socket.gaierror as e:
            # DNS resolution failure
            if attempt < max_retries:
                logger.warning(
                    "dns_resolution_failed_retry | url=%s | attempt=%d/%d | error=%s",
                    url[:80], attempt + 1, max_retries + 1, str(e)
                )
                time.sleep(backoff)
                backoff *= 2
            else:
                logger.warning("dns_resolution_failed_final | url=%s | error=%s", url[:80], str(e))
                return None
                
        except (Timeout, ConnectionError) as e:
            # Network timeout or connection errors
            if attempt < max_retries:
                logger.warning(
                    "network_error_retry | url=%s | attempt=%d/%d | error=%s",
                    url[:80], attempt + 1, max_retries + 1, str(e)
                )
                time.sleep(backoff)
                backoff *= 2
            else:
                logger.warning("network_error_final | url=%s | error=%s", url[:80], str(e))
                return None
                
        except RequestException as e:
            # Other request errors (no retry)
            logger.warning("request_failed | url=%s | error=%s", url[:80], str(e))
            return None
    
    return None


def analyze_redirects(url: str) -> Dict[str, Any]:
    """
    Production redirect analyzer:
    - Manual redirect handling (no auto-follow)
    - Prevent infinite loops
    - Capture full redirect chain safely
    - Retry transient DNS/network failures
    """

    chain: List[str] = []
    visited = set()

    current_url = url

    try:
        for hop in range(MAX_REDIRECTS):

            if current_url in visited:
                logger.warning("redirect_loop_detected | %s", current_url)
                break

            visited.add(current_url)

            response = _fetch_with_retry(current_url)
            
            if response is None:
                # Network failure after retries - stop redirect chain
                logger.info("redirect_chain_stopped_network_failure | url=%s | hops=%d", current_url[:80], hop)
                break

            status = response.status_code

            # Check redirect status codes
            if status in (301, 302, 303, 307, 308):
                location = response.headers.get("Location")

                if not location:
                    break

                next_url = urljoin(current_url, location)

                if not SecureCrawler.is_safe_url(next_url):
                    logger.warning("ssrf_redirect_blocked | %s", next_url[:80])
                    break

                chain.append(next_url)
                current_url = next_url
            else:
                break

        final_url = current_url

        return {
            "redirect_chain": chain,
            "final_url": final_url,
            "redirect_count": len(chain),
            "has_redirect": len(chain) > 0
        }

    except Exception as e:
        logger.warning("redirect_analysis_failed | %s", str(e))
        return {
            "redirect_chain": [],
            "final_url": url,
            "redirect_count": 0,
            "has_redirect": False
        }