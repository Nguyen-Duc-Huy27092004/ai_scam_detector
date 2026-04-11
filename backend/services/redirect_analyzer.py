import requests
from typing import Dict, Any, List
from urllib.parse import urljoin

from utils.logger import logger


MAX_REDIRECTS = 5
TIMEOUT = 5

_DEFAULT_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
}


def analyze_redirects(url: str) -> Dict[str, Any]:
    """
    Production redirect analyzer:
    - Manual redirect handling (no auto-follow)
    - Prevent infinite loops
    - Capture full redirect chain safely
    """

    chain: List[str] = []
    visited = set()

    current_url = url

    try:
        for _ in range(MAX_REDIRECTS):

            if current_url in visited:
                logger.warning("redirect_loop_detected | %s", current_url)
                break

            visited.add(current_url)

            try:
                response = requests.get(
                    current_url,
                    headers=_DEFAULT_HEADERS,
                    timeout=TIMEOUT,
                    allow_redirects=False
                )
            except Exception as e:
                logger.warning("redirect_step_failed | %s", str(e))
                break

            status = response.status_code

            # Check redirect status codes
            if status in (301, 302, 303, 307, 308):
                location = response.headers.get("Location")

                if not location:
                    break

                next_url = urljoin(current_url, location)

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