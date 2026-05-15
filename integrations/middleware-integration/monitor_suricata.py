import time
import json
import os
import sys
import subprocess
from datetime import datetime, timedelta

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

try:
    from main_scoring import get_threat_analysis
except ImportError:
    print("❌ Error Fatal: File 'main_scoring.py' tidak ditemukan!")
    sys.exit(1)

# ─── KONFIGURASI WAZUH & PATH ────────────────────────────────────────────────
CDB_LIST_PATH = '/var/ossec/etc/lists/malware-hashes'
LOG_FILE = "/var/ossec/logs/alerts/alerts.json"
FIM_STATE_FILE = "fim_state.json"
IGNORE_PROTO = ('dns', 'dhcp', 'ntp', 'mdns', 'ssdp', 'arp')

def append_to_cdb_silently(sha256_hash: str, malware_name: str):
    if not sha256_hash: return
    if os.path.exists(CDB_LIST_PATH):
        with open(CDB_LIST_PATH, 'r') as f:
            if sha256_hash in f.read(): return
    try:
        with open(CDB_LIST_PATH, 'a') as f:
            f.write(f"{sha256_hash}:{malware_name}\n")
        subprocess.run(['/var/ossec/bin/ossec-makelists'], check=True, stdout=subprocess.DEVNULL)
        print(f"✅ [CDB] Hash {sha256_hash} berhasil ditambahkan!")
    except Exception as e:
        pass

def trigger_block_ip_log(src_ip: str):
    print(f"[*] [SOAR] Bersiap menulis Surat Perintah Blokir untuk IP: {src_ip}...")
    log_file = "/var/log/chimera_soar.json"
    
    payload = {
        "chimera": {"action": "block-ip"},
        "data": {
            "target": {
                "src_ip": src_ip
            }
        }
    }
    
    try:
        with open(log_file, "a") as f:
            f.write(json.dumps(payload) + "\n")
        print(f"✅ [SOAR] BERHASIL! Surat perintah dikirim ke Wazuh Manager.")
    except Exception as e:
        print(f"❌ [SOAR] Gagal menulis log lokal: {e}")

def check_and_clean_fim_state(target_hash: str):
    if not os.path.exists(FIM_STATE_FILE): return None
    try:
        with open(FIM_STATE_FILE, 'r') as f: state = json.load(f)
    except json.JSONDecodeError: return None

    now = datetime.now()
    active_state = {}
    matched_data = None

    for h, data in state.items():
        ts = datetime.fromisoformat(data['ts'])
        if now - ts <= timedelta(minutes=10):
            active_state[h] = data
            if h == target_hash: matched_data = data

    if len(active_state) != len(state):
        with open(FIM_STATE_FILE, 'w') as f: json.dump(active_state, f, indent=2)
    return matched_data

def follow_log(filepath: str):
    if not os.path.exists(filepath): sys.exit(1)
    with open(filepath, "r", encoding="utf-8") as f:
        f.seek(0, 2)
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.1)
                continue
            yield line

def process_suricata(json_line: str):
    try:
        log = json.loads(json_line)
    except json.JSONDecodeError: return

    data_block = log.get('data', {})
    event_type = data_block.get('event_type', '')
    
    if event_type == 'fileinfo' and (sha256_sur := data_block.get('fileinfo', {}).get('sha256')):
        app_proto = data_block.get('app_proto', '').lower()
        if app_proto in IGNORE_PROTO: return

        # Mengecek korelasi dengan log FIM yang sudah diskor
        fim_data = check_and_clean_fim_state(sha256_sur)
        
        if fim_data:
            file_path = fim_data['path']
            src_ip = data_block.get('src_ip', '127.0.0.1')
            filename = os.path.basename(file_path)

            print(f"\n[!] Trigger [SURICATA CORRELATED] → {filename}")
            print(f"    Hash : {sha256_sur[:24]}...")
            print(f"    Src IP : {src_ip}")

            try:
                # Menyesuaikan dengan alur logikamu: Skoring IP dimulai!
                print(f"[*] [DEBUG-API] Korelasi FIM ditemukan! Hash telah dikonfirmasi.")
                print(f"[*] [DEBUG-API] Memulai proses pemindaian (Scan) skoring khusus untuk IP {src_ip}...")
                
                analysis_data = get_threat_analysis(
                    file_hash=sha256_sur, 
                    src_ip=src_ip, 
                    dest_ip=data_block.get('dest_ip', '127.0.0.1'),
                    file_path=file_path, 
                    source="suricata"
                )

                if analysis_data:
                    scores = analysis_data.get('scores', {})
                    status_ancaman = scores.get('status', 'UNKNOWN')
                    ip_score_value = scores.get('final_score', 0)
                    
                    print(f"[*] [ANALISIS] Hasil Scan IP selesai! Skor: {ip_score_value} | Status: {status_ancaman}")
                    
                    if status_ancaman == 'MALICIOUS':
                        print("[+] [EKSEKUSI] IP terbukti Malicious! Melakukan mitigasi SOAR...")
                        target = analysis_data.get('target', {})
                        
                        append_to_cdb_silently(target.get('file_hash'), target.get('filename', 'Unknown'))
                        
                        target_ip = target.get('src_ip') or src_ip
                        if target_ip:
                            trigger_block_ip_log(target_ip)
                    else:
                        print(f"[-] [ANALISIS] IP tidak berstatus Malicious. Pemblokiran dibatalkan.")
                else:
                    print("❌ [ANALISIS] Modul skoring gagal memberikan hasil.")
                    
            except Exception as e:
                print(f"❌ [SOAR] Terjadi error saat proses pemindaian IP: {e}")

if __name__ == "__main__":
    print("[*] Terminal 2: Monitor Suricata Aktif!")
    print("[*] Menunggu deteksi FIM untuk memulai pemindaian (Scan) IP penyerang...")
    for new_line in follow_log(LOG_FILE):
        process_suricata(new_line)