
# torintel_scan_full.py
# Consolidated Tor intelligence scanner (single-file). 
# NOTE: For lawful, research, and investigative use only. Ensure Tor is running locally.
# Create by ThreatInsights - https://threatinsights.net

import requests
from bs4 import BeautifulSoup
import re
import json
import hashlib
import argparse
from urllib.parse import urljoin, urlparse
import socks
import socket
import ssl
import spacy
import time
import os
from collections import deque
from datetime import datetime, timezone

# Load spaCy model (ensure en_core_web_sm is installed)
try:
    nlp = spacy.load("en_core_web_sm")
except Exception:
    print("[!] spaCy model 'en_core_web_sm' not found. Run: python -m spacy download en_core_web_sm")
    raise

PROXIES = {
    'http': 'socks5h://127.0.0.1:9050',
    'https': 'socks5h://127.0.0.1:9050'
}

DEFAULT_PORTS = [21,22,23,25,53,80,110,143,443,587,8080,3306,6379]

KEYWORD_RULES = {
    "ransomware": ["your files have been encrypted","decrypt","ransom","monero","double extortion"],
    "espionage": ["APT","nation-state","cyberwarfare","espionage","cyber operation"],
    "malware": ["backdoor","rat","keylogger","payload","dropper","cobalt strike"],
    "marketplace": ["buy drugs","fake passport","cc dump","escrow","vendor panel"],
    "forums": ["register","threads","users online","topics","moderator"]
}

PRIORITY_ENTITIES = ["FSB","GCHQ","NSA","CIA","MI6","Mossad","APT","Sandworm","Fancy Bear"]

SSRF_PATHS = ["/admin","/debug","/test","/api","/config","/.env","/health","/server-status","/phpinfo.php","/phpmyadmin/"]
SSRF_PAYLOADS = [
    "http://127.0.0.1:80",
    "http://localhost:8000",
    "file:///etc/passwd",
    "http://169.254.169.254/latest/meta-data/"
]

TOOL_VERSION = "torintel_scan 1.7"

def iso_now():
    return datetime.now(timezone.utc).isoformat()

def sha256_bytes(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()

def sha256_text(t: str) -> str:
    return hashlib.sha256(t.encode('utf-8','ignore')).hexdigest()

def ensure_dir(path):
    os.makedirs(path, exist_ok=True)

def write_jsonl(path, obj):
    with open(path,'a',encoding='utf-8') as f:
        f.write(json.dumps(obj, ensure_ascii=False) + "\n")

# Optional WARC support
try:
    from warcio.warcwriter import WARCWriter
    from io import BytesIO
    HAS_WARCIO = True
except Exception:
    HAS_WARCIO = False

# Optional Playwright
try:
    from playwright.sync_api import sync_playwright
    HAS_PLAYWRIGHT = True
except Exception:
    HAS_PLAYWRIGHT = False

# BTC helpers
BECH32_PREFIXES = ("bc1",)
def btc_classify(addr: str):
    info = {"address": addr, "valid": False, "type": None, "network": "btc"}
    a = addr.strip()
    if a.lower().startswith(BECH32_PREFIXES):
        if 14 <= len(a) <= 90:
            info.update(valid=True, type="bech32")
        return info
    try:
        alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
        num = 0
        for c in a:
            num = num*58 + alphabet.index(c)
        payload = num.to_bytes((num.bit_length()+7)//8, "big")
        pad = 0
        for ch in a:
            if ch == "1": pad += 1
            else: break
        payload = b"\x00"*pad + payload
        if len(payload) < 5: return info
        version = payload[0]
        checksum = payload[-4:]
        vh160 = payload[:-4]
        import hashlib as _hl
        if _hl.sha256(_hl.sha256(vh160).digest()).digest()[:4] != checksum:
            return info
        if version == 0x00: info.update(valid=True, type="p2pkh")
        elif version == 0x05: info.update(valid=True, type="p2sh")
        else: info.update(valid=True, type=f"base58_v{version}")
        return info
    except Exception:
        return info

def load_btc_cache(path):
    if not os.path.exists(path): return {}
    try:
        with open(path,'r') as f: return json.load(f)
    except Exception:
        return {}

def save_btc_cache(path, data):
    try:
        with open(path,'w') as f: json.dump(data, f, indent=2)
    except Exception:
        pass

def btc_query_blockstream(addr, proxies, timeout=20):
    base = "https://blockstream.info/api"
    try:
        r = requests.get(f"{base}/address/{addr}", proxies=proxies, timeout=timeout)
        if r.status_code != 200: return {}
        js = r.json()
        out = {
            "balance": js.get("chain_stats",{}).get("funded_txo_sum",0) - js.get("chain_stats",{}).get("spent_txo_sum",0),
            "total_received": js.get("chain_stats",{}).get("funded_txo_sum",0),
            "tx_count": js.get("chain_stats",{}).get("tx_count",0),
            "provider":"blockstream"
        }
        txs = requests.get(f"{base}/address/{addr}/txs", proxies=proxies, timeout=timeout)
        if txs.status_code == 200:
            out["recent_txids"] = [t.get("txid") for t in txs.json()[:5] if t.get("txid")]
        return out
    except Exception:
        return {}

def btc_query_sochain(addr, proxies, timeout=20):
    net="BTC"; out={"provider":"sochain"}
    try:
        b = requests.get(f"https://sochain.com/api/v2/get_address_balance/{net}/{addr}", proxies=proxies, timeout=timeout).json()
        out["balance"] = float(b.get("data",{}).get("confirmed_balance",0.0))
    except Exception:
        pass
    try:
        r = requests.get(f"https://sochain.com/api/v2/get_address_received/{net}/{addr}", proxies=proxies, timeout=timeout).json()
        out["total_received"] = float(r.get("data",{}).get("confirmed_received_value",0.0))
    except Exception:
        pass
    try:
        t = requests.get(f"https://sochain.com/api/v2/get_tx_received/{net}/{addr}", proxies=proxies, timeout=timeout).json()
        txs = t.get("data",{}).get("txs",[])
        out["tx_count"]=len(txs)
        out["recent_txids"]=[x.get("txid") for x in txs[:5] if x.get("txid")]
    except Exception:
        pass
    return out

def btc_live_recon(addresses, provider, proxies, cache, timeout=20):
    intel={}
    for addr in addresses:
        if not addr: continue
        if cache.get(addr,{}).get("live"):
            intel[addr]=cache[addr]; continue
        try:
            data = btc_query_sochain(addr, proxies, timeout=timeout) if provider=="sochain" else btc_query_blockstream(addr, proxies, timeout=timeout)
        except Exception:
            data={}
        intel[addr]={"live":data}
    return intel

# Clearnet enrich
try:
    from ipwhois import IPWhois
    HAS_IPWHOIS=True
except Exception:
    HAS_IPWHOIS=False

def whois_ip(ip):
    if not HAS_IPWHOIS: return {}
    try:
        data = IPWhois(ip).lookup_rdap(asn_methods=["dns","whois","http"])
        return {
            "asn": data.get("asn"),
            "asn_description": data.get("asn_description"),
            "asn_country_code": data.get("asn_country_code"),
            "network": (data.get("network",{}) or {}).get("name"),
            "cidr": (data.get("network",{}) or {}).get("cidr")
        }
    except Exception:
        return {}

def enrich_clearnet_hosts(resolution_map, pdns_provider=None, pdns_key=None):
    enriched={}
    for host, ip in (resolution_map or {}).items():
        if not ip:
            enriched[host]={"ip":None}
            continue
        info={"ip":ip}
        who=whois_ip(ip)
        if who: info.update(who)
        if pdns_provider=="securitytrails" and pdns_key:
            try:
                h={"APIKEY":pdns_key}
                r=requests.get(f"https://api.securitytrails.com/v1/history/{host}/dns/a", headers=h, timeout=20)
                if r.status_code==200:
                    js=r.json()
                    info["pdns_a_history_count"]=len(js.get("records",[]))
            except Exception:
                pass
        enriched[host]=info
    return enriched

# HIBP
HIBP_API = "https://haveibeenpwned.com/api/v3/breachedaccount/{account}?truncateResponse=true"
def hibp_lookup(email, api_key, user_agent="torintel/1.0"):
    if not api_key: return {}
    try:
        headers={"hibp-api-key":api_key,"User-Agent":user_agent}
        r=requests.get(HIBP_API.format(account=email), headers=headers, timeout=20)
        if r.status_code==200:
            return {"breaches":[b.get("Name") for b in r.json()]}
        elif r.status_code in (404,400):
            return {"breaches":[]}
        else:
            return {"error":f"status_{r.status_code}"}
    except Exception:
        return {}

def breach_enrich(emails, hibp_key=None):
    out={}
    for e in set(emails or []):
        res=hibp_lookup(e, hibp_key)
        if res: out[e]=res
    return out

# Mirror detection
def _tokens(text):
    return re.findall(r"[a-z0-9]{3,}", (text or "").lower())

def simhash64(text, bits=64):
    v=[0]*bits
    for tok in _tokens(text):
        h = int(hashlib.md5(tok.encode()).hexdigest(),16)
        for i in range(bits):
            v[i] += 1 if (h >> i) & 1 else -1
    fp=0
    for i in range(bits):
        if v[i] >= 0:
            fp |= (1<<i)
    return fp

def hamming(a,b):
    x=a^b
    c=0
    while x:
        x &= x-1
        c += 1
    return c

def mirror_detect(current, index_path="corpus_index.json", threshold=8):
    idx={}
    if os.path.exists(index_path):
        try:
            with open(index_path,'r',encoding='utf-8') as f:
                idx=json.load(f)
        except Exception:
            idx={}
    text = current.get("_raw_text","")
    sh = simhash64(text)
    fav = current.get("favicon_hash")
    candidates=[]
    for url, rec in idx.items():
        try:
            d = hamming(sh, int(rec.get("simhash",0)))
            same_fav = (fav and fav == rec.get("favicon_hash"))
            if d <= threshold or same_fav:
                candidates.append({"url":url,"hamming":d,"same_favicon":same_fav})
        except Exception:
            continue
    idx[current.get("url")] = {"simhash": str(sh), "favicon_hash": fav}
    try:
        with open(index_path,'w',encoding='utf-8') as f: json.dump(idx,f,indent=2)
    except Exception:
        pass
    return candidates

def fetch_page(url):
    try:
        response = requests.get(url, proxies=PROXIES, timeout=20)
        return response
    except Exception as e:
        print(f"[!] Error fetching {url}: {e}")
        return None

def tag_keywords(text):
    tags=set(); lowered=text.lower()
    for category, patterns in KEYWORD_RULES.items():
        for pattern in patterns:
            if pattern.lower() in lowered:
                tags.add(category); break
    return list(tags)

def extract_named_entities(text):
    doc = nlp(text)
    entities = [(ent.text, ent.label_) for ent in doc.ents]
    priority_flags = [ent for ent in entities if any(flag.lower() in ent[0].lower() for flag in PRIORITY_ENTITIES)]
    return entities, list(set([ent[0] for ent in priority_flags]))

def compute_correlation_score(metadata):
    score=0
    if metadata.get("favicon_hash"): score+=1
    if metadata.get("btc_addresses"): score+=1
    if metadata.get("xmr_addresses"): score+=1
    if metadata.get("emails"): score+=1
    if metadata.get("pgp_keys"): score+=1
    if metadata.get("contact_handles"): score+=1
    if metadata.get("clearnet_links"): score+=1
    if metadata.get("priority_mentions"): score += len(metadata["priority_mentions"])
    return score

def resolve_clearnet_domains(domains):
    resolved={}
    for domain in domains:
        try:
            parsed=urlparse(domain)
            host=parsed.netloc or parsed.path
            ip=socket.gethostbyname(host)
            resolved[host]=ip
        except Exception:
            resolved[host]=None
    return resolved

def extract_js_endpoints(soup, base_url):
    js_links=[urljoin(base_url, tag.get('src')) for tag in soup.find_all('script', src=True)]
    js_keywords=[]
    for js_url in js_links:
        try:
            r=requests.get(js_url, proxies=PROXIES, timeout=10)
            js_keywords += re.findall(r'/api/[a-z0-9_/-]+|admin[_-]?panel|token|key|/auth/[a-z]+', r.text, re.I)
        except Exception:
            continue
    return list(set(js_keywords))

def fetch_tls_cert(onion_host):
    try:
        context=ssl.create_default_context()
        s=socks.socksocket(); s.set_proxy(socks.SOCKS5, "127.0.0.1", 9050)
        s.connect((onion_host, 443))
        ss=context.wrap_socket(s, server_hostname=onion_host)
        cert=ss.getpeercert()
        return cert
    except Exception:
        return {}

def fingerprint_hidden_service(url):
    timings=[]
    try:
        for _ in range(3):
            start=time.time(); r=requests.get(url, proxies=PROXIES, timeout=10); end=time.time()
            timings.append(round(end-start,3)); time.sleep(1)
        return {"avg_response_time": round(sum(timings)/len(timings),3), "response_times": timings}
    except Exception:
        return {"avg_response_time": None, "response_times": []}

def detect_header_leaks(headers):
    leaks={}
    for header in ["X-Forwarded-For","X-Real-IP","Via","X-Host"]:
        if header in headers: leaks[header]=headers[header]
    return leaks

def test_ssrf_lfi(base_url):
    test_results={}
    for path in SSRF_PATHS:
        full_url = urljoin(base_url, path)
        for payload in SSRF_PAYLOADS:
            try:
                r=requests.post(full_url, data={"url":payload}, proxies=PROXIES, timeout=10)
                if any(key in r.text.lower() for key in ["root:x","meta-data","localhost","/bin/bash"]):
                    test_results[f"{full_url} -> {payload}"] = "Possible SSRF/LFI response"
            except Exception:
                continue
    return test_results

def scan_ports(onion_url, ports=DEFAULT_PORTS):
    domain = urlparse(onion_url).netloc or onion_url.replace("http://","").replace("https://","").strip("/")
    open_ports=[]; port_banners={}
    for port in ports:
        try:
            s = socks.socksocket(); s.set_proxy(socks.SOCKS5, "127.0.0.1", 9050)
            s.settimeout(5); s.connect((domain, port))
            open_ports.append(port)
            try:
                banner = s.recv(1024).decode(errors="ignore").strip(); port_banners[port]=banner
            except Exception:
                port_banners[port]=""
            s.close()
        except Exception:
            continue
    return {"ports": open_ports, "banners": port_banners}

def fetch_favicon_hash(base_url):
    try:
        favicon_url = urljoin(base_url, "/favicon.ico")
        response = requests.get(favicon_url, proxies=PROXIES, timeout=10)
        return hashlib.md5(response.content).hexdigest()
    except Exception:
        return None

def fetch_headers(response):
    return dict(response.headers)

def fetch_robots_txt(base_url):
    try:
        robots_url = urljoin(base_url, "/robots.txt")
        r=requests.get(robots_url, proxies=PROXIES, timeout=10)
        return r.text if r.status_code==200 else None
    except Exception:
        return None

# Misconfig analysis
IP_URL_RE = re.compile(r"https?://(?:\d{1,3}\.){3}\d{1,3}")
ADMIN_PATH_RE = re.compile(r"/(admin|administrator|wp-admin|login|cpanel|phpmyadmin)(/|$)", re.I)
TOR2WEB_RE = re.compile(r"tor2web|onion.to|onion.top|onion.cab|onion.city", re.I)

def analyze_misconfig(soup, base_url, response, metadata):
    findings={"clearnet_embeds": [], "ip_embeds": [], "admin_endpoints":[],"server_version_exposed":False,
              "cors_wildcard":False,"no_tls":False,"form_actions_clearnet":[],"tor2web_indicators":[],
              "risky_open_ports":[],"score":0}
    for res in metadata.get("external_resources", []):
        if isinstance(res,str) and res.startswith("http") and ".onion" not in res:
            findings["clearnet_embeds"].append(res)
        if isinstance(res,str) and IP_URL_RE.search(res):
            findings["ip_embeds"].append(res)
        if isinstance(res,str) and TOR2WEB_RE.search(res):
            findings["tor2web_indicators"].append(res)
    for form in soup.find_all("form"):
        action = (form.get("action") or "").strip()
        if action.startswith("http") and ".onion" not in action:
            findings["form_actions_clearnet"].append(action)
    for a in soup.find_all("a", href=True):
        href=a["href"]
        if ADMIN_PATH_RE.search(href):
            findings["admin_endpoints"].append(urljoin(base_url, href))
    server = (response.headers.get("Server") or "") if response else ""
    if re.search(r"(nginx|apache|openresty|lighttpd|iis)[^\s]*\/[0-9]", server, re.I):
        findings["server_version_exposed"]=True
    aco=(response.headers.get("Access-Control-Allow-Origin") or "") if response else ""
    acc=(response.headers.get("Access-Control-Allow-Credentials") or "") if response else ""
    try:
        if aco=="*" and acc.lower()=="true":
            findings["cors_wildcard"]=True
    except Exception:
        pass
    ports = metadata.get("open_ports",[])
    if 80 in ports and 443 not in ports: findings["no_tls"]=True
    risky = [p for p in ports if p in (22,23,3306,6379)]
    if risky: findings["risky_open_ports"]=risky
    score=0
    score += 2*len(findings["clearnet_embeds"]) + 3*len(findings["ip_embeds"]) + 1*len(findings["admin_endpoints"]) \
             + (2 if findings["server_version_exposed"] else 0) + (2 if findings["cors_wildcard"] else 0) \
             + (1 if findings["no_tls"] else 0) + 2*len(findings["form_actions_clearnet"]) \
             + 2*len(findings["tor2web_indicators"]) + 2*len(findings["risky_open_ports"]) \
             + (2 if metadata.get("header_leaks") else 0)
    findings["score"]=score
    return findings

# Evidence capture
def evidence_capture(url, case_dir, warc_path=None, tor_socks="127.0.0.1:9050", user_agent=None,
                     wait_selector=None, wait_keywords=None, max_wait=120,
                     timeline=False, snapshot_every=5, newnym=False, control_port=9051, control_password=None):
    results={"screenshot":None,"screenshot_sha256":None,"dom_html":None,"dom_sha256":None,"warc":None,
             "wait_elapsed":0,"queue_detected":False}
    def tor_newnym():
        try:
            from stem.control import Controller
            with Controller.from_port(port=control_port) as c:
                if control_password:
                    c.authenticate(password=control_password)
                else:
                    c.authenticate()
                c.signal(c.Signal.NEWNYM)
                return True
        except Exception:
            return False
    if HAS_PLAYWRIGHT:
        ensure_dir(case_dir)
        try:
            with sync_playwright() as p:
                browser = p.chromium.launch(headless=True, args=[f"--proxy-server=socks5://{tor_socks}",
                                                                "--disable-blink-features=AutomationControlled"])
                ctx = browser.new_context(ignore_https_errors=True, user_agent=user_agent, timezone_id="UTC", locale="en-US")
                page = ctx.new_page()
                start=time.time()
                page.goto(url, wait_until="domcontentloaded", timeout=45000)
                QUEUE_HINTS=["please wait","just a moment","checking your browser","in a queue","security check"]
                def is_queue_state(text):
                    t=(text or "").lower()
                    return any(h in t for h in QUEUE_HINTS)
                next_snap=time.time()
                while True:
                    elapsed=time.time()-start
                    results["wait_elapsed"]=round(elapsed,2)
                    content=page.content()
                    title=(page.title() or "")
                    ready=False
                    if wait_selector:
                        try:
                            page.wait_for_selector(wait_selector, state="visible", timeout=1000)
                            ready=True
                        except Exception:
                            ready=False
                    if wait_keywords and not ready:
                        low=(content or "").lower()
                        if any(k.lower() in low for k in wait_keywords):
                            ready=True
                    queue_now = is_queue_state(title) or is_queue_state(content)
                    results["queue_detected"]=results["queue_detected"] or queue_now
                    big_enough = len(content) > 5000
                    if ready or (not queue_now and big_enough):
                        break
                    if timeline and time.time() >= next_snap:
                        shot_path = os.path.join(case_dir, f"timeline_{int(elapsed)}s.png")
                        try:
                            page.screenshot(path=shot_path, full_page=True)
                        except Exception:
                            pass
                        next_snap = time.time() + max(1, snapshot_every)
                    if elapsed >= max_wait:
                        break
                    if newnym and int(elapsed) % 20 == 0:
                        tor_newnym()
                        time.sleep(2)
                    time.sleep(1)
                shot_path=os.path.join(case_dir,"screenshot.png")
                try:
                    page.screenshot(path=shot_path, full_page=True)
                    results["screenshot"]=shot_path
                    with open(shot_path,'rb') as f:
                        results["screenshot_sha256"]=sha256_bytes(f.read())
                except Exception:
                    pass
                try:
                    dom=page.content()
                    results["dom_html"]=os.path.join(case_dir,"dom.html")
                    with open(results["dom_html"],'w',encoding='utf-8') as f:
                        f.write(dom)
                    results["dom_sha256"]=sha256_text(dom)
                except Exception:
                    pass
                ctx.close(); browser.close()
        except Exception:
            pass
    if warc_path and HAS_WARCIO:
        try:
            ensure_dir(os.path.dirname(warc_path))
            with open(warc_path,'ab') as stream:
                writer = WARCWriter(stream, gzip=True)
                r = requests.get(url, proxies=PROXIES, timeout=45, allow_redirects=True)
                http_headers = [(k,v) for k,v in r.headers.items()]
                payload = r.content
                record = writer.create_warc_record(url,'response', payload=BytesIO(payload), http_headers=http_headers)
                writer.write_record(record)
                results["warc"]=warc_path
        except Exception:
            pass
    return results

def extract_metadata(html, base_url, response, active_tests=False, hibp_key=None, pdns_provider=None, pdns_key=None, mirror_index=None):
    soup=BeautifulSoup(html,"html.parser")
    text=soup.get_text()
    external_resources=[]
    for tag in soup.find_all(['script','link','img']):
        val = tag.get('src') or tag.get('href')
        if val: external_resources.append(val)
    named_entities, priority_mentions = extract_named_entities(text)
    js_keywords_found = extract_js_endpoints(soup, base_url)
    clearnet_links = list(set(re.findall(r"http[s]?://[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", text)))
    resolved_hosts = resolve_clearnet_domains(clearnet_links)
    enriched_hosts = enrich_clearnet_hosts(resolved_hosts, pdns_provider=pdns_provider, pdns_key=pdns_key) if (pdns_provider or pdns_key) else enrich_clearnet_hosts(resolved_hosts)
    data = {
        "title": soup.title.string.strip() if soup.title else "No Title",
        "emails": re.findall(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", text),
        "pgp_keys": re.findall(r"-----BEGIN PGP PUBLIC KEY BLOCK-----(.*?)-----END PGP PUBLIC KEY BLOCK-----", text, re.DOTALL),
        "btc_addresses": re.findall(r"\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b", text),
        "xmr_addresses": re.findall(r"4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}", text),
        "onion_links": list(set(re.findall(r"http[s]?://[a-z2-7]{56}\.onion", text))),
        "clearnet_links": clearnet_links,
        "clearnet_resolution": resolved_hosts,
        "clearnet_host_info": enriched_hosts,
        "external_resources": external_resources,
        "login_forms": [form.get('action') for form in soup.find_all('form') if soup.find('input', {'type':'password'})],
        "directory_listing": 'Index of /' in soup.title.string if soup.title else False,
        "leak_indicators": list(set(re.findall(r"root:toor|admin:1234|<!--.*?-->|\.git|\.env", text))),
        "tags": tag_keywords(text),
        "named_entities": named_entities,
        "priority_mentions": priority_mentions,
        "cms_frameworks_detected": re.findall(r"wordpress|drupal|joomla|laravel|vue|react|angular|django", text, re.I),
        "file_leaks": re.findall(r'https?://[^\s"]+\.(zip|tar\.gz|sql|7z|db)', text),
        "contact_handles": re.findall(r'@[A-Za-z0-9_]{3,}|t\.me/\S+|protonmail\.com', text),
        "js_keywords_found": js_keywords_found,
        "cookies": response.cookies.get_dict() if response else {},
        "header_leaks": detect_header_leaks(response.headers) if response else {},
        "ssrf_lfi_results": test_ssrf_lfi(base_url) if active_tests else {}
    }
    data["_raw_text"]=text
    if hibp_key and data.get("emails"):
        data["breach_hits"]=breach_enrich(data.get("emails"), hibp_key)
    data["misconfig_findings"]=analyze_misconfig(soup, base_url, response, data)
    if mirror_index:
        try:
            data["mirror_candidates"]=mirror_detect({"url":base_url,"_raw_text":text,"favicon_hash":None if 'favicon_hash' not in data else data.get('favicon_hash')}, index_path=mirror_index)
        except Exception:
            data["mirror_candidates"]=[]
    data["correlation_score"]=compute_correlation_score(data)
    return data

def save_results(url, metadata, output_file):
    with open(output_file,'a',encoding='utf-8') as f:
        f.write(json.dumps({"url":url, **metadata}, indent=2, ensure_ascii=False) + "\n")

ONION_RE = re.compile(r"https?://[a-z2-7]{56}\.onion(?:/[\w\-./?%&=]*)?", re.I)
def normalize_onion(url):
    if not url.startswith("http"): url="http://"+url
    return url.rstrip()

def crawl_onions(seeds, max_depth, delay, output_file, active_tests=False, evidence=None, hibp_key=None, pdns_provider=None, pdns_key=None, mirror_index=None):
    visited=set(); discovered=set(); q=deque([(normalize_onion(s),0) for s in seeds])
    while q:
        url, depth = q.popleft()
        if url in visited or depth>max_depth: continue
        visited.add(url)
        resp = fetch_page(url)
        if not resp or resp.status_code>=500: continue
        md = extract_metadata(resp.text, url, resp, active_tests=active_tests, hibp_key=hibp_key, pdns_provider=pdns_provider, pdns_key=pdns_key, mirror_index=mirror_index)
        md["favicon_hash"]=fetch_favicon_hash(url)
        md["headers"]=fetch_headers(resp)
        md["robots_txt"]=fetch_robots_txt(url)
        md["tls_certificate"]=fetch_tls_cert(urlparse(url).netloc or url.strip("/").replace("http://",""))
        port_result = scan_ports(url)
        md["open_ports"]=port_result["ports"]
        md["port_banners"]=port_result["banners"]
        md["hidden_service_fingerprint"]=fingerprint_hidden_service(url)
        if evidence:
            ev = evidence_capture(url, evidence.get("case_dir"), warc_path=evidence.get("warc_path"))
            md["evidence"]={"captured_at":iso_now(),"tool_version":TOOL_VERSION, **ev, "html_sha256": sha256_text(resp.text)}
            audit={"time":iso_now(),"event":"page_captured","url":url,"status":resp.status_code,"bytes":len(resp.content),"html_sha256":md["evidence"]["html_sha256"], "screenshot":ev.get("screenshot"), "screenshot_sha256":ev.get("screenshot_sha256"), "warc":ev.get("warc"), "tor_proxy":PROXIES.get('http')}
            write_jsonl(evidence.get("audit_path"), audit)
        btc_info={}
        for a in md.get("btc_addresses", []): btc_info[a]={"classification":btc_classify(a)}
        md["btc_intel"]=btc_info
        save_results(url, md, output_file)
        for link in md.get("onion_links", []):
            link = normalize_onion(link)
            if link not in visited:
                q.append((link, depth+1)); discovered.add(link)
        time.sleep(delay)
    return discovered

def main():
    parser = argparse.ArgumentParser(description="Scan/crawl .onion sites for intel and evidentiary capture.")
    parser.add_argument("--url", help="Single .onion URL to scan")
    parser.add_argument("--output", default="torintel_output.jsonl", help="Output JSONL file")
    parser.add_argument("--btc-recon", action="store_true", help="Enable live Bitcoin recon via public APIs")
    parser.add_argument("--btc-provider", choices=["blockstream","sochain"], default="blockstream", help="Blockchain data source")
    parser.add_argument("--btc-cache", default="btc_intel_cache.json", help="Path to local BTC intel cache")
    parser.add_argument("--active-tests", action="store_true", help="Enable active SSRF/LFI tests (use with caution)")
    parser.add_argument("--crawl", action="store_true", help="Enable crawler mode")
    parser.add_argument("--seed-file", help="Path to file with seed onion URLs (one per line)")
    parser.add_argument("--max-depth", type=int, default=1, help="Max crawl depth")
    parser.add_argument("--delay", type=float, default=1.0, help="Delay between requests in seconds")
    parser.add_argument("--discovered-out", default="discovered_onions.txt", help="Where to write newly found onions")
    parser.add_argument("--evidence", action="store_true", help="Enable evidence capture (screenshots, DOM, hashes, audit log)")
    parser.add_argument("--case-dir", default=None, help="Directory to store evidence bundle (auto if not set)")
    parser.add_argument("--warc", action="store_true", help="Also save a WARC of the main page (requires warcio)")
    parser.add_argument("--enrich-clearnet", action="store_true", help="Add ASN/WHOIS for clearnet pivots")
    parser.add_argument("--pdns-provider", choices=["securitytrails"], help="Passive DNS provider (requires API key)")
    parser.add_argument("--pdns-key", help="Passive DNS API key (provider-specific)")
    parser.add_argument("--breach-check", action="store_true", help="Query HIBP for scraped emails (requires key)")
    parser.add_argument("--hibp-key", help="HaveIBeenPwned API key")
    parser.add_argument("--mirror-detect", action="store_true", help="Detect mirrors/clones using SimHash & favicon")
    parser.add_argument("--index-file", default="corpus_index.json", help="Path to similarity index file")
    args = parser.parse_args()

    evidence=None
    if args.evidence:
        base = args.case_dir or f"case_{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}"
        case_dir = os.path.abspath(base)
        ensure_dir(case_dir)
        audit_path = os.path.join(case_dir, "audit.jsonl")
        warc_path = os.path.join(case_dir, "capture.warc.gz") if args.warc else None
        evidence={"case_dir":case_dir,"audit_path":audit_path,"warc_path":warc_path}
        write_jsonl(audit_path, {"time":iso_now(),"event":"run_start","tool_version":TOOL_VERSION,"proxy":PROXIES.get('http')})

    hibp_key = args.hibp_key if args.breach_check else None
    pdns_provider = args.pdns_provider if (args.enrich_clearnet or args.pdns_provider) else None
    pdns_key = args.pdns_key if args.pdns_provider else None
    mirror_index = args.index_file if args.mirror_detect else None

    if args.crawl:
        seeds=set()
        if args.url: seeds.add(args.url)
        if args.seed_file and os.path.exists(args.seed_file):
            with open(args.seed_file,'r',encoding='utf-8') as f:
                for line in f:
                    line=line.strip()
                    if not line: continue
                    seeds.add(line)
        if not seeds:
            print("[!] No seeds provided. Use --url or --seed-file.")
            exit(1)
        print(f"[*] Starting crawl with {len(seeds)} seed(s), depth={args.max_depth}")
        new_ones = crawl_onions(seeds, args.max_depth, args.delay, args.output, active_tests=args.active_tests, evidence=evidence, hibp_key=hibp_key, pdns_provider=pdns_provider, pdns_key=pdns_key, mirror_index=mirror_index)
        if new_ones:
            with open(args.discovered_out,'a',encoding='utf-8') as f:
                for u in sorted(new_ones): f.write(u + "\n")
        print(f"[+] Crawl complete. Discovered {len(new_ones)} new onion link(s). Saved to {args.discovered_out}")
        if evidence: write_jsonl(evidence.get("audit_path"), {"time":iso_now(),"event":"run_end"})
        exit(0)

    if not args.url:
        print("[!] --url is required when not using --crawl")
        if evidence: write_jsonl(evidence.get("audit_path"), {"time":iso_now(),"event":"run_end","error":"missing_url"})
        exit(1)

    response = fetch_page(args.url)
    if response and response.status_code==200:
        metadata = extract_metadata(response.text, args.url, response, active_tests=args.active_tests, hibp_key=hibp_key, pdns_provider=pdns_provider, pdns_key=pdns_key, mirror_index=mirror_index)
        metadata["favicon_hash"] = fetch_favicon_hash(args.url)
        metadata["headers"] = fetch_headers(response)
        metadata["robots_txt"] = fetch_robots_txt(args.url)
        metadata["tls_certificate"] = fetch_tls_cert(urlparse(args.url).netloc or args.url.strip("/").replace("http://",""))
        port_result = scan_ports(args.url)
        metadata["open_ports"] = port_result["ports"]
        metadata["port_banners"] = port_result["banners"]
        metadata["hidden_service_fingerprint"] = fingerprint_hidden_service(args.url)
        if evidence:
            ev = evidence_capture(args.url, evidence.get("case_dir"), warc_path=evidence.get("warc_path"))
            metadata["evidence"] = {"captured_at":iso_now(),"tool_version":TOOL_VERSION, **ev, "html_sha256": sha256_text(response.text)}
            write_jsonl(evidence.get("audit_path"), {"time":iso_now(),"event":"page_captured","url":args.url,"status":response.status_code,"bytes":len(response.content),"html_sha256":metadata["evidence"]["html_sha256"], "screenshot":ev.get("screenshot"), "screenshot_sha256":ev.get("screenshot_sha256"), "warc":ev.get("warc"), "tor_proxy":PROXIES.get('http')})
        btc_info={}
        for a in metadata.get("btc_addresses", []): btc_info[a]={"classification":btc_classify(a)}
        if args.btc_recon and metadata.get("btc_addresses"):
            cache = load_btc_cache(args.btc_cache)
            live = btc_live_recon(metadata["btc_addresses"], args.btc_provider, PROXIES, cache)
            for addr, dat in live.items():
                btc_info.setdefault(addr, {}).update(dat)
                cache[addr] = {**cache.get(addr, {}), **dat}
            save_btc_cache(args.btc_cache, cache)
        metadata["btc_intel"] = btc_info
        save_results(args.url, metadata, args.output)
        print(f"[+] Scan complete. Correlation Score: {metadata['correlation_score']}. Misconfig Score: {metadata['misconfig_findings']['score']}. Data saved to {args.output}")
    else:
        print("[!] Failed to fetch or scan the target.")
    if evidence: write_jsonl(evidence.get("audit_path"), {"time":iso_now(),"event":"run_end"})

if __name__ == "__main__":
    main()
