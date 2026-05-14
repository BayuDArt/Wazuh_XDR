import os
import time
import requests
from dotenv import load_dotenv

# Load env variables
dotenv_path = os.path.join(os.path.dirname(__file__), '..', '.env')
load_dotenv(dotenv_path)

API_KEY = os.getenv("ABUSEIPDB_API_KEY")

# Menggunakan Session untuk performa (Reuse TCP Connection)
ABUSEIPDB_SESSION = requests.Session()
ABUSEIPDB_SESSION.headers.update({
    "Accept": "application/json",
    "Key": API_KEY 
})

def check_abuseipdb(ioc_value, ioc_type, retries=3, delay=2):
    
    # AbuseIPDB hanya untuk IPv4/IPv6
    if ioc_type != 'ip':
        return "N/A"

    if not API_KEY:
        print("[!] Error AbuseIPDB: API Key tidak ditemukan di .env")
        return "Auth Error"
    
    url = "https://api.abuseipdb.com/api/v2/check"
    params = {
        "ipAddress": ioc_value,
        "maxAgeInDays": "90"
    }

    for attempt in range(1, retries + 1):
        try:
            # Timeout set ke 15 detik
            response = ABUSEIPDB_SESSION.get(url, params=params, timeout=15)

            # --- HANDLING STATUS CODE ---
            
            # 1. Auth Error
            if response.status_code in [401, 402]:
                return "Auth Error"

            # 2. Rate Limit (Biasanya limit harian habis)
            if response.status_code == 429:
                # Jika 429, biasanya percuma retry karena limit harian habis
                return "Rate Limit"

            # 3. Server Error (500, 502, 503) -> Masih bisa retry
            if response.status_code >= 500:
                print(f"⚠️  AbuseIPDB Server Error {response.status_code}. Retrying...")
                time.sleep(delay)
                continue

            # Jika sukses
            response.raise_for_status()
            
            data = response.json().get("data")
            if not data:
                return "Error No Data"
            
            return str(data.get("abuseConfidenceScore", 0))

        # --- HANDLING NETWORK ERROR ---
        except (requests.exceptions.Timeout, requests.exceptions.ConnectionError) as e:
            print(f"⚠️  AbuseIPDB Timeout/Connection (percobaan {attempt}/{retries})...")
            if attempt < retries:
                time.sleep(delay)
                continue
            else:
                return "Error: Timeout"
                
        except Exception as e:
            print(f"[!] Error AbuseIPDB Fatal: {e}")
            return "Error"

    return "Error: Failed"