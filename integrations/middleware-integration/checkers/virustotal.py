import vt
import time
import random
from itertools import cycle
from collections import deque
from dotenv import load_dotenv
import os

load_dotenv()

API_KEYS = [
    os.getenv("VT_API_KEY1"),
    os.getenv("VT_API_KEY2")
]

MAX_REQUESTS_PER_MINUTE_PER_KEY = 4
MAX_RETRIES = 3

key_cycle = cycle(API_KEYS)
api_request_times = {key: deque() for key in API_KEYS}


VT_OBJECT_PATHS = {
    "hash": "files",
    "ip": "ip_addresses",
    "domain": "domains"
}

def check_virustotal(ioc_value, ioc_type):
    
    path_segment = VT_OBJECT_PATHS.get(ioc_type)
    if not path_segment:
        print(f"❌ Error VT: Tipe IoC tidak dikenal: {ioc_type}")
        return "Error: Invalid IoC Type"

    vt_path = f"/{path_segment}/{ioc_value}"
    api_key = next(key_cycle)

    now = time.time()
    timestamps = api_request_times[api_key]
    while timestamps and now - timestamps[0] > 60:
        timestamps.popleft()

    if len(timestamps) >= MAX_REQUESTS_PER_MINUTE_PER_KEY:
        oldest_timestamp = timestamps[0]
        wait_time = 60 - (now - oldest_timestamp) + 1
        if wait_time > 0:
            print(f"⏳ VT Rate limit tercapai untuk key {api_key[:4]}... Menunggu {wait_time:.1f} detik.")
            time.sleep(wait_time)
    api_request_times[api_key].append(time.time())


    for attempt in range(MAX_RETRIES):
        try:
            with vt.Client(api_key) as client:
                try:
                    obj = client.get_object(vt_path)
                    stats = obj.last_analysis_stats

                    valid_keys = ['malicious', 'undetected', 'harmless', 'suspicious']
                    filtered_stats = {k: stats.get(k, 0) for k in valid_keys}
                    total_verdicts = sum(filtered_stats.values())
                    malicious = filtered_stats['malicious']

                    if total_verdicts == 0:
                        score_str = "0/0"
                    else:
                        score_str = f"{malicious}/{total_verdicts}"

                    threat_label = ""
                    if hasattr(obj, 'popular_threat_classification'):
                        label_info = obj.popular_threat_classification
                        if label_info and label_info.get('suggested_threat_label'):
                            threat_label = label_info.get('suggested_threat_label')

                    return f"{score_str} {threat_label}".strip()

                except vt.error.APIError as e:
                    if "NotFoundError" in str(e):
                        return "Not Found"
                    if "NotAllowedError" in str(e):
                        print(f"🚨 Terkena ban sementara pada key {api_key[:4]}... Tidur 65 detik.")
                        time.sleep(65)
                        continue
                    else:
                        raise e

        except Exception as e:
            err_msg = str(e)
            if "QuotaExceededError" in err_msg:
                print(f"⚠️ VT Quota harian habis untuk key {api_key[:4]}... Coba kunci lain...")
                try:
                    api_key = next(key_cycle)
                    api_request_times.setdefault(api_key, deque())
                    continue
                except StopIteration:
                    return "Error: Quota semua key habis"

            if attempt < MAX_RETRIES - 1:
                sleep_time = 2 ** attempt + random.uniform(0.5, 1.5)
                print(f"⏳ Gagal, mencoba lagi dalam {sleep_time:.1f} detik...")
                time.sleep(sleep_time)
            else:
                return f"Error: {err_msg[:60]}"

    return "Error: Max retries exceeded"