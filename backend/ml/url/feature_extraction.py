import re
from urllib.parse import urlparse, parse_qs


class URLFeatureExtractor:

    SUSPICIOUS_WORDS = {
        "login", "verify", "bank", "account",
        "secure", "update", "confirm", "password",
        "urgent", "action", "alert", "click"
    }

    @staticmethod
    def extract_features(url: str):

        parsed = urlparse(url)

        hostname = parsed.netloc.lower()
        path = parsed.path
        query = parsed.query

        features = {}

        # ==========================
        # Basic structure
        # ==========================

        features["NumDots"] = url.count(".")
        features["SubdomainLevel"] = max(hostname.count(".") - 1, 0)
        features["PathLevel"] = path.count("/")
        features["UrlLength"] = len(url)

        features["NumDash"] = url.count("-")
        features["NumDashInHostname"] = hostname.count("-")

        features["AtSymbol"] = 1 if "@" in url else 0
        features["TildeSymbol"] = 1 if "~" in url else 0
        features["NumUnderscore"] = url.count("_")
        features["NumPercent"] = url.count("%")

        features["NumQueryComponents"] = len(parse_qs(query))
        features["NumAmpersand"] = url.count("&")
        features["NumHash"] = url.count("#")

        features["NumNumericChars"] = sum(c.isdigit() for c in url)

        features["NoHttps"] = 1 if parsed.scheme != "https" else 0

        # ==========================
        # Random string detection (entropy nhẹ)
        # ==========================

        def entropy(s):
            import math
            prob = [float(s.count(c)) / len(s) for c in set(s)]
            return -sum(p * math.log2(p) for p in prob)

        features["RandomString"] = 1 if entropy(hostname) > 3.5 else 0

        # ==========================
        # IP address
        # ==========================

        ip_pattern = r"^\d{1,3}(\.\d{1,3}){3}$"
        features["IpAddress"] = 1 if re.match(ip_pattern, hostname) else 0

        # ==========================
        # Domain tricks
        # ==========================

        features["DomainInSubdomains"] = 1 if hostname.count(".") > 2 else 0
        features["DomainInPaths"] = 1 if hostname in path else 0
        features["HttpsInHostname"] = 1 if "https" in hostname else 0

        # ==========================
        # Lengths
        # ==========================

        features["HostnameLength"] = len(hostname)
        features["PathLength"] = len(path)
        features["QueryLength"] = len(query)

        features["DoubleSlashInPath"] = 1 if "//" in path else 0

        # ==========================
        # Suspicious words
        # ==========================

        features["NumSensitiveWords"] = sum(
            1 for w in URLFeatureExtractor.SUSPICIOUS_WORDS
            if w in url.lower()
        )

        features["EmbeddedBrandName"] = 0  # cần list brand mới làm được

        # ==========================
        # Những feature cần HTML → set default
        # ==========================

        features["PctExtHyperlinks"] = 0
        features["PctExtResourceUrls"] = 0
        features["ExtFavicon"] = 0
        features["InsecureForms"] = 0
        features["RelativeFormAction"] = 0
        features["ExtFormAction"] = 0
        features["AbnormalFormAction"] = 0
        features["PctNullSelfRedirectHyperlinks"] = 0
        features["FrequentDomainNameMismatch"] = 0
        features["FakeLinkInStatusBar"] = 0
        features["RightClickDisabled"] = 0
        features["PopUpWindow"] = 0
        features["SubmitInfoToEmail"] = 0
        features["IframeOrFrame"] = 0
        features["MissingTitle"] = 0
        features["ImagesOnlyInForm"] = 0

        # ==========================
        # RT features (tạm set 0)
        # ==========================

        features["SubdomainLevelRT"] = 0
        features["UrlLengthRT"] = 0
        features["PctExtResourceUrlsRT"] = 0
        features["AbnormalExtFormActionR"] = 0
        features["ExtMetaScriptLinkRT"] = 0
        features["PctExtNullSelfRedirectHyperlinksRT"] = 0

        return features

    @staticmethod
    def get_feature_names():
        return [
            "NumDots","SubdomainLevel","PathLevel","UrlLength","NumDash",
            "NumDashInHostname","AtSymbol","TildeSymbol","NumUnderscore",
            "NumPercent","NumQueryComponents","NumAmpersand","NumHash",
            "NumNumericChars","NoHttps","RandomString","IpAddress",
            "DomainInSubdomains","DomainInPaths","HttpsInHostname",
            "HostnameLength","PathLength","QueryLength","DoubleSlashInPath",
            "NumSensitiveWords","EmbeddedBrandName","PctExtHyperlinks",
            "PctExtResourceUrls","ExtFavicon","InsecureForms",
            "RelativeFormAction","ExtFormAction","AbnormalFormAction",
            "PctNullSelfRedirectHyperlinks","FrequentDomainNameMismatch",
            "FakeLinkInStatusBar","RightClickDisabled","PopUpWindow",
            "SubmitInfoToEmail","IframeOrFrame","MissingTitle",
            "ImagesOnlyInForm","SubdomainLevelRT","UrlLengthRT",
            "PctExtResourceUrlsRT","AbnormalExtFormActionR",
            "ExtMetaScriptLinkRT","PctExtNullSelfRedirectHyperlinksRT"
        ]

    @staticmethod
    def get_feature_vector(features: dict):

        return [features.get(name, 0) for name in URLFeatureExtractor.get_feature_names()]