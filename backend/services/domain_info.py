import socket
import requests
import whois
from datetime import datetime
from typing import Dict, Any

def get_domain_info(domain: str) -> Dict[str, Any]:
    """
    Get basic domain info: IP, location, ASN, registrar, owner, dates, nameservers.
    Non-blocking, timeouts configured. Returns empty strings/lists if data is missing.
    """
    result = {
        "ip": "",
        "location": "",
        "asn": "",
        "isp": "",
        "registrar": "",
        "owner": "",
        "created_date": "",
        "expiry_date": "",
        "nameservers": []
    }
    
    if not domain:
        return result

    # 1. Resolve IP (timeout <= 2s)
    ip = ""
    try:
        socket.setdefaulttimeout(2.0)
        ip = socket.gethostbyname(domain)
        result["ip"] = ip
    except Exception:
        pass

    # 2. Call IP API (timeout <= 2s)
    if ip:
        try:
            # Using ip-api.com, free and fast without API key
            resp = requests.get(f"http://ip-api.com/json/{ip}?fields=country,city,isp,as", timeout=2.0)
            if resp.status_code == 200:
                data = resp.json()
                location = []
                if data.get("city"): location.append(data.get("city"))
                if data.get("country"): location.append(data.get("country"))
                result["location"] = ", ".join(location) if location else ""
                
                # 'as' field in ip-api contains ASN
                result["asn"] = data.get("as", "")
                result["isp"] = data.get("isp", "")
        except Exception:
            pass

    # 3. Get WHOIS (timeout <= 3s)
    # The _safe_future in URLAnalysisPipeline will also enforce a hard 5s timeout
    try:
        w = whois.whois(domain)
        if w:
            result["registrar"] = w.registrar or ""
            
            # owner / name
            owner = w.name or w.org or w.emails or ""
            if isinstance(owner, list):
                owner = owner[0]
            result["owner"] = str(owner) if owner else ""

            # dates formatting
            def format_date(d):
                if not d: return ""
                if isinstance(d, list): d = d[0]
                if isinstance(d, datetime): return d.strftime("%d/%m/%Y")
                return str(d)

            result["created_date"] = format_date(w.creation_date)
            result["expiry_date"] = format_date(w.expiration_date)

            # nameservers
            ns = w.name_servers
            if not ns:
                ns = []
            elif isinstance(ns, str):
                ns = [ns]
            result["nameservers"] = [str(n).lower() for n in ns if n]

    except Exception:
        pass

    # Ensure data cleaning: None -> "", list None -> []
    for k, v in result.items():
        if v is None:
            if isinstance(result.get(k, ""), list):
                result[k] = []
            else:
                result[k] = ""
                
    return result
