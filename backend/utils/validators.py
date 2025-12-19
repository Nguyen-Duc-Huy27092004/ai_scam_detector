import re

def is_valid_url(url: str) -> bool:
    if not url or " " in url:
        return False

    regex = re.compile(
        r'^(https?:\/\/)'              # http:// or https://
        r'(([A-Za-z0-9-]+\.)+[A-Za-z]{2,})'  # domain
        r'(:\d+)?'                     # optional port
        r'(\/[^\s]*)?$'                # path + query
    )

    return bool(regex.match(url))
