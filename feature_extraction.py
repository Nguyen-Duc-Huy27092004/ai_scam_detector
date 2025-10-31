import re
import urllib.parse
import numpy as np

def extract_features_from_url(url):
    parsed = urllib.parse.urlparse(url)
    hostname = parsed.netloc or ""
    path = parsed.path or ""
    query = parsed.query or ""

    def count_digits(s): 
        return sum(c.isdigit() for c in s)
    
    def has_ip(h): 
        return 1 if re.match(r"(\d{1,3}\.){3}\d{1,3}", h) else 0
    
    def has_https(h): 
        return 1 if "https" in h else 0

    features = [
        url.count('.'),                                      # 1. NumDots
        hostname.count('.') - 1 if hostname else 0,          # 2. SubdomainLevel
        path.count('/'),                                     # 3. PathLevel
        len(url),                                            # 4. UrlLength
        url.count('-'),                                      # 5. NumDash
        hostname.count('-'),                                 # 6. NumDashInHostname
        1 if '@' in url else 0,                              # 7. AtSymbol
        1 if '~' in url else 0,                              # 8. TildeSymbol
        url.count('_'),                                      # 9. NumUnderscore
        url.count('%'),                                      # 10. NumPercent
        len(query.split('&')) if query else 0,               # 11. NumQueryComponents
        query.count('&'),                                    # 12. NumAmpersand
        url.count('#'),                                      # 13. NumHash
        count_digits(url),                                   # 14. NumNumericChars
        0 if url.startswith("https") else 1,                 # 15. NoHttps
        1 if re.search(r"[A-Za-z]{5,}\d+[A-Za-z]{2,}", url) else 0,  # 16. RandomString
        has_ip(hostname),                                    # 17. IpAddress
        1 if hostname.split('.')[0] in path else 0,          # 18. DomainInSubdomains
        1 if hostname.split('.')[0] in path else 0,          # 19. DomainInPaths
        has_https(hostname),                                 # 20. HttpsInHostname
        len(hostname),                                       # 21. HostnameLength
        len(path),                                           # 22. PathLength
        len(query),                                          # 23. QueryLength
        1 if '//' in path else 0,                            # 24. DoubleSlashInPath
        0,                                                   # 25. NumSensitiveWords (placeholder)
        0,                                                   # 26. EmbeddedBrandName (placeholder)
        0, 0, 0, 0, 0, 0, 0,                                 # 27–33. PctExtHyperlinks -> ExtFormAction
        0, 0, 0, 0, 0, 0, 0,                                 # 34–40. AbnormalFormAction -> PopUpWindow
        0, 0, 0, 0,                                          # 41–44. SubmitInfoToEmail -> ImagesOnlyInForm
        0, 0, 0, 0, 0, 0,                                    # 45–50. SubdomainLevelRT -> PctExtNullSelfRedirectHyperlinksRT
    ]

    # Đảm bảo đúng 48 đặc trưng
    features = features[:48]  # cắt nếu dư
    while len(features) < 48:
        features.append(0)

    return np.array(features).reshape(1, -1)
