"""
Screenshot capture service for websites.

Captures screenshots of websites for analysis.
"""

import subprocess
import uuid
from pathlib import Path
from typing import Optional
from utils.logger import logger
from config import SCREENSHOTS_DIR, SCREENSHOT_TIMEOUT, USER_AGENT

# Try to import required libraries
try:
    from selenium import webdriver
    from selenium.webdriver.common.by import By
    from selenium.webdriver.support.ui import WebDriverWait
    from selenium.webdriver.support import expected_conditions as EC
    SELENIUM_AVAILABLE = True
except ImportError:
    SELENIUM_AVAILABLE = False
    logger.warning("selenium not available | using_playwright")

try:
    from playwright.sync_api import sync_playwright
    PLAYWRIGHT_AVAILABLE = True
except ImportError:
    PLAYWRIGHT_AVAILABLE = False
    logger.warning("playwright not available")


class ScreenshotService:
    """Service for capturing website screenshots."""
    
    @staticmethod
    def capture_with_playwright(url: str) -> Optional[str]:
        """
        Capture screenshot using Playwright.
        
        Args:
            url: URL to capture
            
        Returns:
            str: Path to screenshot file or None
        """
        if not PLAYWRIGHT_AVAILABLE:
            logger.warning("playwright_not_available")
            return None
        
        try:
            screenshot_filename = f"{uuid.uuid4()}.png"
            screenshot_path = SCREENSHOTS_DIR / screenshot_filename
            
            with sync_playwright() as p:
                browser = p.chromium.launch(headless=True)
                page = browser.new_page()
                
                page.goto(url, wait_until='domcontentloaded', timeout=SCREENSHOT_TIMEOUT * 1000)
                page.screenshot(path=str(screenshot_path), full_page=True)
                
                browser.close()
            
            logger.info("screenshot_captured | url=%s | path=%s", url[:50], screenshot_filename)
            return str(screenshot_path)
            
        except Exception as e:
            logger.error("screenshot_capture_failed_playwright | error=%s", str(e))
            return None
    
    @staticmethod
    def capture_with_selenium(url: str) -> Optional[str]:
        """
        Capture screenshot using Selenium.
        
        Args:
            url: URL to capture
            
        Returns:
            str: Path to screenshot file or None
        """
        if not SELENIUM_AVAILABLE:
            logger.warning("selenium_not_available")
            return None
        
        try:
            screenshot_filename = f"{uuid.uuid4()}.png"
            screenshot_path = SCREENSHOTS_DIR / screenshot_filename
            
            options = webdriver.ChromeOptions()
            options.add_argument('--headless')
            options.add_argument('--no-sandbox')
            options.add_argument('--disable-dev-shm-usage')
            options.add_argument(f'user-agent={USER_AGENT}')
            
            driver = webdriver.Chrome(options=options)
            driver.set_page_load_timeout(SCREENSHOT_TIMEOUT)
            
            driver.get(url)
            driver.save_screenshot(str(screenshot_path))
            driver.quit()
            
            logger.info("screenshot_captured | url=%s | path=%s", url[:50], screenshot_filename)
            return str(screenshot_path)
            
        except Exception as e:
            logger.error("screenshot_capture_failed_selenium | error=%s", str(e))
            return None
    
    @staticmethod
    def capture(url: str) -> Optional[str]:
        """
        Capture website screenshot with fallback strategies.
        
        Args:
            url: URL to capture
            
        Returns:
            str: Path to screenshot file or None
        """
        try:
            # Try Playwright first
            if PLAYWRIGHT_AVAILABLE:
                result = ScreenshotService.capture_with_playwright(url)
                if result:
                    return result
            
            # Fallback to Selenium
            if SELENIUM_AVAILABLE:
                result = ScreenshotService.capture_with_selenium(url)
                if result:
                    return result
            
            logger.warning("no_screenshot_engine_available")
            return None
            
        except Exception as e:
            logger.error("screenshot_service_error | error=%s", str(e))
            return None


def capture_website(url: str) -> Optional[str]:
    """
    Convenience function to capture website screenshot.
    
    Args:
        url: URL to capture
        
    Returns:
        str: Path to screenshot file or None
    """
    return ScreenshotService.capture(url)
