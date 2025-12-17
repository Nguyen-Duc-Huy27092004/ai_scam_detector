import re
import urllib.parse
import numpy as np

def extract_features_from_url(url: str) -> np.ndarray:
    parsed = urllib.parse.urlparse(url)

    hostname = parsed.netloc
    path = parsed.path
    query = parsed.query

    def count_digits(s):
        return sum(c.isdigit() for c in s)

    def has_ip_address(host):
        return 1 if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host) else 0

    features = []

    features.append(len(url))                 
    features.append(len(hostname))          
    features.append(len(path))           
    features.append(len(query))           

    features.append(url.count('.'))           
    features.append(hostname.count('.'))          
    features.append(url.count('-'))          
    features.append(url.count('_'))            
    features.append(url.count('%'))             
    features.append(url.count('@'))                  
    features.append(url.count('#'))                  
    features.append(url.count('//') - 1)           

    features.append(count_digits(url))       
    features.append(1 if re.search(r"[A-Za-z]{4,}\d+", url) else 0)  
    features.append(1 if "login" in url.lower() else 0)         
    features.append(1 if "verify" in url.lower() else 0)        
    features.append(1 if "update" in url.lower() else 0)      
    features.append(1 if "secure" in url.lower() else 0)      

    features.append(0 if url.startswith("https") else 1)           
    features.append(has_ip_address(hostname))                      
    features.append(1 if hostname.startswith("www") else 0)        
    features.append(len(hostname.split('.')))                  

    features.append(query.count('&'))                         
    features.append(1 if '=' in query else 0)             

    features.append(path.count('/'))                             
    features.append(1 if hostname.split('.')[0] in path else 0)     

    while len(features) < 48:
        features.append(0)

    return np.array(features)
