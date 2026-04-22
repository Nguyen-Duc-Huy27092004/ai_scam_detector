"""
Screenshot capture service for websites.
"""

import uuid
from pathlib import Path
from typing import Optional

from services.async_crawler import SecureCrawler
from utils.logger import logger
from utils.config import SCREENSHOTS_DIR, SCREENSHOT_TIMEOUT, USER_AGENT


# ==========================
# Engine availability
# ==========================

try:
    from playwright.sync_api import sync_playwright
    PLAYWRIGHT_AVAILABLE = True
except ImportError:
    PLAYWRIGHT_AVAILABLE = False
    logger.warning("playwright_not_available")

try:
    from selenium import webdriver
    SELENIUM_AVAILABLE = True
except ImportError:
    SELENIUM_AVAILABLE = False
    logger.warning("selenium_not_available")


# ==========================
# Utils
# ==========================

def _ensure_dir() -> Optional[Path]:
    try:
        path = Path(SCREENSHOTS_DIR)
        path.mkdir(parents=True, exist_ok=True)
        return path
    except Exception as e:
        logger.error("screenshot_dir_create_failed | %s", str(e))
        return None


# ==========================
# Service
# ==========================

class ScreenshotService:

    # ======================
    # Playwright (BEST)
    # ======================
    @staticmethod
    def capture_with_playwright(url: str) -> Optional[str]:
        if not PLAYWRIGHT_AVAILABLE:
            return None

        base_dir = _ensure_dir()
        if not base_dir:
            return None

        screenshot_path = base_dir / f"{uuid.uuid4()}.png"

        try:
            with sync_playwright() as p:
                browser = p.chromium.launch(headless=True)

                context = browser.new_context(user_agent=USER_AGENT)
                page = context.new_page()

                # retry 1 lần nếu fail
                try:
                    page.goto(url, timeout=SCREENSHOT_TIMEOUT * 1000)
                except Exception as e:
                    logger.warning("playwright_retry | %s", str(e))
                    page.goto(url, timeout=SCREENSHOT_TIMEOUT * 2000)

                page.wait_for_timeout(1000)

                page.screenshot(
                    path=str(screenshot_path),
                    full_page=True
                )

                context.close()   # 🔥 FIX leak
                browser.close()

            logger.info(
                "screenshot_playwright_success | file=%s",
                screenshot_path.name
            )

            return str(screenshot_path)

        except Exception as e:
            logger.error(
                "screenshot_playwright_failed | %s | %s",
                url[:50],
                str(e)
            )
            return None

    # ======================
    # Selenium (fallback)
    # ======================
    @staticmethod
    def capture_with_selenium(url: str) -> Optional[str]:
        if not SELENIUM_AVAILABLE:
            return None

        base_dir = _ensure_dir()
        if not base_dir:
            return None

        screenshot_path = base_dir / f"{uuid.uuid4()}.png"
        driver = None

        try:
            options = webdriver.ChromeOptions()
            options.add_argument("--headless=new")
            options.add_argument("--no-sandbox")
            options.add_argument("--disable-dev-shm-usage")
            options.add_argument(f"user-agent={USER_AGENT}")

            driver = webdriver.Chrome(options=options)

            driver.set_page_load_timeout(SCREENSHOT_TIMEOUT)
            driver.set_window_size(1920, 1080)   # 🔥 FIX UI

            try:
                driver.get(url)
            except Exception as e:
                logger.warning("selenium_retry | %s | %s", url[:50], str(e))
                driver.get(url)

            driver.save_screenshot(str(screenshot_path))

            logger.info(
                "screenshot_selenium_success | file=%s",
                screenshot_path.name
            )

            return str(screenshot_path)

        except Exception as e:
            logger.error(
                "screenshot_selenium_failed | %s | %s",
                url[:50],
                str(e)
            )
            return None

        finally:
            if driver:
                try:
                    driver.quit()
                except Exception as e:
                    logger.debug("selenium_quit_failed | %s", str(e))

    # ======================
    # Main
    # ======================
    @staticmethod
    def capture(url: str) -> Optional[str]:
        try:
            if not SecureCrawler.is_safe_url(url):
                logger.warning("ssrf_screenshot_blocked | url=%s", url[:80])
                return None
            # ưu tiên playwright
            if PLAYWRIGHT_AVAILABLE:
                result = ScreenshotService.capture_with_playwright(url)
                if result:
                    return result

            # fallback selenium
            if SELENIUM_AVAILABLE:
                result = ScreenshotService.capture_with_selenium(url)
                if result:
                    return result

            logger.warning("no_screenshot_engine_available")
            return None

        except Exception as e:
            logger.error("screenshot_service_error | %s", str(e))
            return None


# ==========================
# Helper
# ==========================

def capture_website(url: str) -> Optional[str]:
    return ScreenshotService.capture(url)