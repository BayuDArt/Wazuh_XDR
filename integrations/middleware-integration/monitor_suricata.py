import time
import json
import os
import sys
import threading
from datetime import datetime

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

try:
    from main_scoring import get_threat_analysis
except ImportError:
    print("❌ Error Fatal: File 'main_scoring.py' tidak ditemukan!")
    sys.exit(1)

# ─── 1. KONFIGURASI PATH ─────────────────────────────────────────────────────
LOG_FILE = "/var/ossec/logs/alerts/alerts.json"
CHIMERA_SOAR_LOG = "/var/log/chimera_soar.json"
IP_CACHE_FILE = "ip_cache.json"
CDB_LIST_PATH = '/var/ossec/etc/lists/malware-hashes'
POINTER_FILE = "suricata_log_pos.txt"
IGNORE_PROTO = ('dns', 'dhcp', 'ntp', 'mdns', 'ssdp', 'arp')

# Kunci (Lock) agar penulisan file Cache JSON aman dari tabrakan Multi-Threading
cache_lock = threading.Lock()

# ─── 2. SISTEM CACHE IP & CDB ────────────────────────────────────────────────
def load_ip_cache():
    """Membaca cache IP dari file JSON."""
    if not os.path.exists(IP_CACHE_FILE):
        return {}
    try:
        with open(IP_CACHE_FILE, 'r') as f:
            return json.load(f)
    except json.JSONDecodeError:
        return {}

def update_ip_cache(src_ip: str, status: str, reason: str):
    """Menyimpan atau memperbarui status IP ke dalam cache dengan aman."""
    with cache_lock: # Mengunci proses agar thread lain antri
        cache = load_ip_cache()
        cache[src_ip] = {
            "status": status,
            "reason": reason,
            "timestamp": datetime.now().isoformat()
        }
        try:
            with open(IP_CACHE_FILE, 'w') as f:
                json.dump(cache, f, indent=4)
        except Exception as e:
            print(f"❌ [CACHE] Gagal menyimpan cache IP: {e}")

def is_hash_in_cdb(target_hash: str) -> bool:
    """Mengecek keberadaan hash di dalam database FIM lokal (CDB List)."""
    if not target_hash or not os.path.exists(CDB_LIST_PATH):
        return False
    try:
        with open(CDB_LIST_PATH, 'r') as f:
            # Membaca baris per baris lebih aman untuk memori
            for line in f:
                if target_hash in line:
                    return True
    except Exception as e:
        print(f"[-] Gagal membaca CDB List: {e}")
    return False

# ─── 3. FUNGSI SOAR (Block Mikrotik) ──────────────────────────────────────────────
def trigger_block_ip_log(src_ip: str, reason: str):
    """Menulis surat perintah SOAR untuk memBlock Mikrotik di MikroTik."""
    print(f"[*] [SOAR] Mengeksekusi Block Mikrotik: {src_ip} (Alasan: {reason})")
    
    payload = {
        "chimera": {"action": "block-mikrotik"},
        "data": {
            "target": {"src_ip": src_ip}
        }
    }
    
    try:
        with open(CHIMERA_SOAR_LOG, "a") as f:
            f.write(json.dumps(payload) + "\n")
        print(f"✅ [SOAR] Surat perintah 'block-mikrotik' sukses dikirim ke Wazuh Manager.")
    except Exception as e:
        print(f"❌ [SOAR] Gagal menulis log lokal: {e}")

# ─── 4. BACKGROUND WORKER (ANALISIS & LOGIKA KEPUTUSAN) ──────────────────────
def run_suricata_analysis(src_ip, dest_ip, file_hash):
    """Berjalan di thread terpisah untuk memproses tugas Suricata secara asinkron."""
    
    # LANGKAH 1: Cek Cache (Apakah IP ini sudah pernah dianalisis?)
    cache = load_ip_cache()
    if src_ip in cache:
        status_lama = cache[src_ip].get("status")
        # Jika sudah diblokir sebelumnya, tidak perlu diulang
        if status_lama == "MALICIOUS":
            print(f"[-] [CACHE] IP {src_ip} sudah ada di daftar MALICIOUS. Melewati analisis.")
            return
        # Jika NORMAL, kita bisa biarkan berlanjut ke pengecekan hash baru

    # LANGKAH 2 (TUGAS KEDUA): Cek Hash ke CDB List Lokal (Jalur Cepat)
    if is_hash_in_cdb(file_hash):
        print(f"🚨 [KORELASI LOKAL] Hash jaringan ditemukan di dalam CDB Malware List!")
        print(f"    Hash: {file_hash[:24]}... -> IP: {src_ip}")
        
        # Simpan ke Cache & Eksekusi SOAR
        update_ip_cache(src_ip, "MALICIOUS", "Matched Local CDB Hash")
        trigger_block_ip_log(src_ip, "Terkorelasi dengan CDB List Lokal")
        return # Hentikan eksekusi, ancaman sudah ditangani

    # LANGKAH 3 (TUGAS PERTAMA): Analisis IP/Hash via Scoring Module API
    print(f"[*] [API] Hash tidak ada di CDB. Memulai analisis skoring untuk IP {src_ip}...")
    try:
        analysis_data = get_threat_analysis(
            file_hash=file_hash, 
            src_ip=src_ip, 
            dest_ip=dest_ip,
            file_path="network_extraction", 
            source="suricata"
        )

        if analysis_data:
            scores = analysis_data.get('scores', {})
            status_ancaman = scores.get('status', 'UNKNOWN')
            ip_score_value = scores.get('final_score', 0)
            
            print(f"[*] [ANALISIS API] IP {src_ip} | Skor: {ip_score_value} | Status: {status_ancaman}")
            
            # Jika terbukti Malicious via API
            if status_ancaman == 'MALICIOUS':
                update_ip_cache(src_ip, "MALICIOUS", "API Scoring Status Malicious")
                trigger_block_ip_log(src_ip, "Dinyatakan Malicious oleh CTI Scoring Engine")
            else:
                # Simpan di cache sebagai NORMAL/SUSPICIOUS agar tidak buang-buang kuota API lagi
                update_ip_cache(src_ip, status_ancaman, "API Scoring Result")
                print(f"[-] [ANALISIS API] IP aman atau sekadar mencurigakan. Tidak diblokir.")
        else:
            print("❌ [ANALISIS API] Modul skoring gagal memberikan hasil.")
            
    except Exception as e:
        print(f"❌ [ERROR] Terjadi kegagalan saat analisis API: {e}")

# ─── 5. PEMBACA LOG ──────────────────────────────────────────────────────────
def process_suricata(json_line: str):
    try:
        log = json.loads(json_line)
    except json.JSONDecodeError: return

    data_block = log.get('data', {})
    
    # Hanya tangkap log jaringan berbasis file (fileinfo) atau Suricata alert umum
    if data_block.get('event_type') != 'fileinfo' and data_block.get('event_type') != 'alert': 
        return

    # Ambil Hash jika ada (dari log fileinfo)
    sha256_sur = data_block.get('fileinfo', {}).get('sha256', '')
    
    if data_block.get('app_proto', '').lower() in IGNORE_PROTO: return

    src_ip = data_block.get('src_ip') or data_block.get('srcip')
    dest_ip = data_block.get('dest_ip') or data_block.get('destip')

    # Abaikan jika tidak ada Source IP (wajib untuk SOAR)
    if not src_ip: return 
    
    # Lempar tugas logika IP & CDB ke Background Thread
    bg_thread = threading.Thread(
        target=run_suricata_analysis, 
        args=(src_ip, dest_ip, sha256_sur)
    )
    bg_thread.start()

def follow_log(filepath: str):
    """Membaca log alerts.json hanya untuk event yang baru masuk."""
    if not os.path.exists(filepath): 
        sys.exit(1)
    
    last_pos = None
    if os.path.exists(POINTER_FILE):
        try:
            with open(POINTER_FILE, 'r') as p:
                last_pos = int(p.read().strip())
        except ValueError: 
            pass

    with open(filepath, "r", encoding="utf-8") as f:
        # Lompat ke paling akhir
        f.seek(0, 2)
        end_pos = f.tell()
        
        # Jika belum ada pointer, atau pointer melebihi ukuran file (log di-rotate)
        if last_pos is None or last_pos > end_pos:
            last_pos = end_pos
            
        # Posisikan pembacaan
        f.seek(last_pos)
        
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.1)
                continue
            
            # Update pointer file
            with open(POINTER_FILE, 'w') as p:
                p.write(str(f.tell()))
                
            yield line

if __name__ == "__main__":
    print("[*] Terminal 2: Monitor Suricata Aktif!")
    print("[*] Mengamankan IP via Cache Memori dan Korelasi CDB Lokal...")
    for new_line in follow_log(LOG_FILE):
        process_suricata(new_line)