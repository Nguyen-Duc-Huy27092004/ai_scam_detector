import re
import math
from urllib.parse import urlparse, parse_qs
from typing import Dict, Any, Optional
from bs4 import BeautifulSoup
from utils.logger import logger


class URLFeatureExtractor:

    SUSPICIOUS_KEYWORDS = {
        'update', 'verify', 'confirm', 'account', 'bank', 'secure',
        'login', 'password', 'urgent', 'action', 'click', 'alert',
        'wallet', 'payment', 'invoice', 'refund'
    }

    SUSPICIOUS_TLDS = {
        'tk', 'ml', 'ga', 'cf', 'xyz', 'top', 'win', 'review'
    }

    @staticmethod
    def _shannon_entropy(s: str) -> float:
        if not s:
            return 0.0
        prob = [float(s.count(c)) / len(s) for c in dict.fromkeys(list(s))]
        return -sum(p * math.log2(p) for p in prob)

    @staticmethod
    def extract_features(url: str, html_content: Optional[str] = None) -> Dict[str, Any]:
        try:
            parsed = urlparse(url)
            domain = parsed.netloc.lower()
            path = parsed.path.lower()
            query = parsed.query.lower()

            features = {}
            signals = []

            # Basic
            features['url_length'] = len(url)
            features['domain_length'] = len(domain)
            features['path_length'] = len(path)
            features['subdomain_count'] = domain.count('.') - 1
            features['digit_count'] = sum(c.isdigit() for c in url)
            features['special_char_count'] = len(re.findall(r'[!@#$%^&*()_+=\[\]{};:,.<>?/]', url))
            features['entropy'] = URLFeatureExtractor._shannon_entropy(domain)

            # HTTPS
            features['has_https'] = 1 if parsed.scheme == 'https' else 0
            if features['has_https'] == 0:
                signals.append("Website không dùng HTTPS")

            # IP address
            ip_pattern = r'\d+\.\d+\.\d+\.\d+'
            features['has_ip_address'] = 1 if re.fullmatch(ip_pattern, domain) else 0
            if features['has_ip_address']:
                signals.append("URL sử dụng địa chỉ IP")

            # TLD
            tld = domain.split('.')[-1]
            features['suspicious_tld'] = 1 if tld in URLFeatureExtractor.SUSPICIOUS_TLDS else 0
            if features['suspicious_tld']:
                signals.append("TLD đáng ngờ")

            # Keywords
            domain_kw = sum(1 for k in URLFeatureExtractor.SUSPICIOUS_KEYWORDS if k in domain)
            path_kw = sum(1 for k in URLFeatureExtractor.SUSPICIOUS_KEYWORDS if k in path)
            query_kw = sum(1 for k in URLFeatureExtractor.SUSPICIOUS_KEYWORDS if k in query)

            features['suspicious_domain_words'] = domain_kw
            features['suspicious_path_words'] = path_kw
            features['suspicious_query_words'] = query_kw

            if domain_kw + path_kw + query_kw > 0:
                signals.append("URL chứa từ khóa lừa đảo")

            # Query params
            features['query_param_count'] = len(parse_qs(query))

            # HTML-based features
            features['has_form'] = 0
            features['has_password_input'] = 0
            features['external_link_ratio'] = 0

            if html_content:
                soup = BeautifulSoup(html_content, "html.parser")
                forms = soup.find_all("form")
                features['has_form'] = 1 if forms else 0
                if forms:
                    signals.append("Trang web có form nhập liệu")

                password_inputs = soup.find_all("input", {"type": "password"})
                features['has_password_input'] = 1 if password_inputs else 0
                if password_inputs:
                    signals.append("Trang web yêu cầu nhập mật khẩu")

                links = soup.find_all("a", href=True)
                external = [a for a in links if domain not in a['href']]
                if links:
                    features['external_link_ratio'] = len(external) / len(links)

            features["_signals"] = signals

            logger.debug("url_features_extracted | url=%s", url[:60])
            return features

        except Exception as e:
            logger.error("feature_extraction_failed | error=%s", str(e))
            return {"url_length": len(url), "_signals": []}

    @staticmethod
    def get_feature_names():
        return [
            'url_length', 'domain_length', 'path_length', 'subdomain_count',
            'digit_count', 'special_char_count', 'entropy', 'has_https',
            'has_ip_address', 'suspicious_tld',
            'suspicious_domain_words', 'suspicious_path_words',
            'suspicious_query_words', 'query_param_count',
            'has_form', 'has_password_input', 'external_link_ratio'
        ]

    @staticmethod
    def get_feature_vector(features: Dict[str, Any]) -> list:
        vector = []
        for name in URLFeatureExtractor.get_feature_names():
            value = features.get(name, 0)
            if isinstance(value, bool):
                value = 1 if value else 0
            vector.append(value)
        return vector