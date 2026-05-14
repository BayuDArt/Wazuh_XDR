import os
import time
import requests

# Mapping tipe IoC ke path OTX API
IOC_TYPE_PATHS_OTX = {
    "hash": "file",
    "ip": "IPv4",
    "domain": "domain"
}

def check_otx(ioc_value, ioc_type, retries=3, delay=5):

    path_segment = IOC_TYPE_PATHS_OTX.get(ioc_type)
    if not path_segment:
        print(f"[!] Error OTX: Tipe IoC tidak dikenal: {ioc_type}")
        return "Error: Invalid IoC Type"

    endpoint = "analysis" if path_segment == "file" else "general"
    url = f"https://otx.alienvault.com/api/v1/indicators/{path_segment}/{ioc_value}/{endpoint}"

    api_key = os.getenv("OTX_API_KEY")

    headers = {
        "User-Agent": "EducationalSecurityResearch/1.0 (contact: your_email@domain.com)",
    }
    if api_key:
        headers["X-OTX-API-KEY"] = api_key

    # Loop Retry
    for attempt in range(1, retries + 1):
        try:
            # PERBAIKAN 1: Naikkan timeout jadi 30 detik
            response = requests.get(url, headers=headers, timeout=30)

            # Jika kena Rate Limit (429)
            if response.status_code == 429:
                print(f"⚠️  Rate limit reached (attempt {attempt}/{retries}). "
                      f"Tunggu {delay}s sebelum retry...")
                time.sleep(delay)
                delay *= 2 
                continue 

            # Jika data tidak ditemukan (404)
            if response.status_code == 404:
                return "none"

            # Jika server error (500, 502, 503) -> Coba lagi
            if response.status_code >= 500:
                print(f"⚠️  OTX Server Error {response.status_code}. Retrying...")
                time.sleep(2)
                continue

            response.raise_for_status()
            data = response.json()

            pulses = 0
            asn = "N/A"

            if endpoint == "general":
                pulses = data.get("pulse_info", {}).get("count", 0)
                asn = data.get("asn", "N/A")
            elif endpoint == "analysis":
                pulses = data.get("general", {}).get("pulse_info", {}).get("count", 0)

            result_parts = []
            if pulses > 0:
                result_parts.append(f"{pulses} pulses")
            if ioc_type == "ip" and asn != "N/A":
                result_parts.append(asn)

            # Sukses
            return " ".join(result_parts) if result_parts else "none"

        # PERBAIKAN 2: Tangkap error Timeout agar bisa RETRY
        except (requests.exceptions.Timeout, requests.exceptions.ConnectionError) as e:
            print(f"⚠️  OTX Timeout/Connection Error (percobaan {attempt}/{retries})...")
            if attempt < retries:
                time.sleep(delay) # Tunggu sebentar lalu coba lagi
                continue
            else:
                # Jika sudah habis kesempatan retry
                return "Error: Timeout"

        except requests.exceptions.RequestException as e:
            print(f"[!] Error OTX request fatal: {e}")
            return "Error: Request Failed"

    print("[!] Gagal menghubungi OTX setelah beberapa kali percobaan.")
    return "Error: Connection Failed"