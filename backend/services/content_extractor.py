"""
Web content extraction service.

Extracts HTML content and text from websites.
"""

from typing import Tuple, Optional
from utils.logger import logger
from config import USER_AGENT, CONTENT_EXTRACTION_TIMEOUT

try:
    import requests
    from bs4 import BeautifulSoup
    WEB_AVAILABLE = True
except ImportError:
    WEB_AVAILABLE = False
    logger.warning("requests/beautifulsoup not available")


class ContentExtractor:
    """Service for extracting web content."""
    
    # Unwanted HTML elements
    UNWANTED_TAGS = ['script', 'style', 'meta', 'link', 'noscript', 'iframe']
    
    @staticmethod
    def extract_from_url(url: str) -> Tuple[Optional[str], Optional[str]]:
        """
        Extract HTML and text content from URL.
        
        Args:
            url: URL to extract from
            
        Returns:
            tuple: (html_content, text_content) or (None, None) if failed
        """
        if not WEB_AVAILABLE:
            logger.warning("web_tools_not_available")
            return None, None
        
        try:
            headers = {
                'User-Agent': USER_AGENT,
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.5',
                'Accept-Encoding': 'gzip, deflate',
                'Connection': 'keep-alive',
            }
            
            response = requests.get(
                url,
                headers=headers,
                timeout=CONTENT_EXTRACTION_TIMEOUT,
                verify=True
            )
            
            if response.status_code != 200:
                logger.warning("http_error | url=%s | status=%d", url[:50], response.status_code)
                return None, None
            
            html_content = response.text
            
            # Parse HTML
            soup = BeautifulSoup(html_content, 'html.parser')
            
            # Remove unwanted elements
            for tag in ContentExtractor.UNWANTED_TAGS:
                for element in soup.find_all(tag):
                    element.decompose()
            
            # Extract text
            text_content = soup.get_text(separator=' ', strip=True)
            
            # Clean up text
            text_content = ' '.join(text_content.split())
            
            logger.info(
                "content_extracted | url=%s | html_len=%d | text_len=%d",
                url[:50],
                len(html_content),
                len(text_content)
            )
            
            return html_content, text_content
            
        except requests.exceptions.Timeout:
            logger.error("content_extraction_timeout | url=%s", url[:50])
            return None, None
        except requests.exceptions.SSLError:
            logger.warning("ssl_error | url=%s | retrying_without_verification", url[:50])
            return None, None
        except Exception as e:
            logger.error("content_extraction_failed | url=%s | error=%s", url[:50], str(e))
            return None, None
    
    @staticmethod
    def extract_metadata(html_content: str) -> dict:
        """
        Extract metadata from HTML.
        
        Args:
            html_content: HTML content string
            
        Returns:
            dict: Extracted metadata
        """
        try:
            soup = BeautifulSoup(html_content, 'html.parser')
            
            metadata = {
                'title': None,
                'description': None,
                'keywords': None,
                'author': None,
                'lang': None,
                'links_count': 0,
                'images_count': 0,
                'forms_count': 0,
                'forms': []
            }
            
            # Title
            title_tag = soup.find('title')
            if title_tag:
                metadata['title'] = title_tag.get_text(strip=True)
            
            # Meta description
            meta_desc = soup.find('meta', attrs={'name': 'description'})
            if meta_desc:
                metadata['description'] = meta_desc.get('content', '')
            
            # Keywords
            meta_keywords = soup.find('meta', attrs={'name': 'keywords'})
            if meta_keywords:
                metadata['keywords'] = meta_keywords.get('content', '')
            
            # Author
            meta_author = soup.find('meta', attrs={'name': 'author'})
            if meta_author:
                metadata['author'] = meta_author.get('content', '')
            
            # Language
            html_tag = soup.find('html')
            if html_tag:
                metadata['lang'] = html_tag.get('lang', '')
            
            # Count elements
            metadata['links_count'] = len(soup.find_all('a'))
            metadata['images_count'] = len(soup.find_all('img'))
            metadata['forms_count'] = len(soup.find_all('form'))
            
            # Extract forms
            for form in soup.find_all('form')[:3]:  # Limit to first 3
                form_data = {
                    'action': form.get('action', ''),
                    'method': form.get('method', 'get'),
                    'fields': len(form.find_all('input'))
                }
                metadata['forms'].append(form_data)
            
            return metadata
            
        except Exception as e:
            logger.error("metadata_extraction_failed | error=%s", str(e))
            return {}
    
    @staticmethod
    def get_domain_from_url(url: str) -> str:
        """
        Extract domain from URL.
        
        Args:
            url: URL string
            
        Returns:
            str: Domain name
        """
        try:
            from urllib.parse import urlparse
            parsed = urlparse(url)
            return parsed.netloc
        except:
            return ""


def extract_from_url(url: str) -> Tuple[Optional[str], Optional[str]]:
    """
    Convenience function to extract content from URL.
    
    Args:
        url: URL to extract from
        
    Returns:
        tuple: (html_content, text_content)
    """
    return ContentExtractor.extract_from_url(url)


def extract_metadata(html_content: str) -> dict:
    """
    Convenience function to extract metadata.
    
    Args:
        html_content: HTML content string
        
    Returns:
        dict: Metadata dictionary
    """
    return ContentExtractor.extract_metadata(html_content)
