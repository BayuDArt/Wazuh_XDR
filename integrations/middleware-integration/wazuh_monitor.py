import time
import json
import os
import sys
import threading
from datetime import datetime, timedelta
from typing import Optional

import requests
import urllib3
import subprocess
# Matikan peringatan SSL jika Wazuh API menggunakan self-signed certificate
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ─── KONFIGURASI WAZUH API ───────────────────────────────────────────────────
WAZUH_API_URL = "https://127.0.0.1:55000"
WAZUH_API_USER = "chimera_api"
WAZUH_API_PASS = "P@ssw0rd2025"
CDB_LIST_PATH = '/var/ossec/etc/lists/malware-hashes'

def append_to_cdb_silently(sha256_hash: str, malware_name: str):
    """
    Menyimpan hash ke file TXT dan langsung mengompilasinya menjadi CDB 
    agar Wazuh bisa menggunakannya secara real-time.
    """
    if not sha256_hash:
        return
        
    # Cek apakah hash sudah ada untuk mencegah duplikasi
    if os.path.exists(CDB_LIST_PATH):
        with open(CDB_LIST_PATH, 'r') as f:
            if sha256_hash in f.read():
                return
                
    try:
        # 1. Tulis hash baru ke file .txt (Format wajib CDB: key:value)
        with open(CDB_LIST_PATH, 'a') as f:
            f.write(f"{sha256_hash}:{malware_name}\n")
            
        # 2. KOMPILASI OTOMATIS: Perbarui file .cdb di sistem Wazuh
        # Ini membuat Wazuh seketika mengenali hash baru tanpa perlu restart service!
        subprocess.run(['/var/ossec/bin/ossec-makelists'], check=True, stdout=subprocess.DEVNULL)
        print(f"✅ [CDB] Hash {sha256_hash} berhasil ditambahkan dan list diperbarui!")
        
    except PermissionError:
        print("❌ [CDB] Error: Skrip butuh akses root/sudo untuk memperbarui list Wazuh.")
    except Exception as e:
        print(f"❌ [CDB] Gagal memperbarui list: {e}")

def trigger_active_response(agent_id: str, file_path: str):
    """
    Menembak Wazuh API secara langsung untuk mengeksekusi Active Response.
    Dokumentasi: Payload menggunakan awalan '!' untuk mengeksekusi script custom 
    secara langsung tanpa memerlukan parameter 'custom' yang ditolak API.
    """
    try:
        # 1. Dapatkan Token Otentikasi
        auth_resp = requests.get(
            f"{WAZUH_API_URL}/security/user/authenticate",
            auth=(WAZUH_API_USER, WAZUH_API_PASS),
            verify=False,
            timeout=5
        )
        if auth_resp.status_code != 200:
            print("❌ [SOAR] Gagal mendapatkan token API Wazuh.")
            return

        token = auth_resp.json().get('data', {}).get('token')

        # 2. Tembakkan Perintah Active Response
        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json"
        }
        
        # PERBAIKAN: Hapus parameter "custom". 
        # Cukup gunakan tanda '!' di awal nama file executable kamu.
        # Ini menyuruh Wazuh mengeksekusi: /var/ossec/active-response/bin/remove-threat
        payload = {
            "command": "remove-threat-Linux", 
            "arguments": [file_path]
        }

        print(f"🔥 [SOAR] Mengirim perintah 'remove-threat-Linux' ke Agent {agent_id} untuk file: {file_path}")
        ar_resp = requests.put(
            f"{WAZUH_API_URL}/active-response?agents_list={agent_id}",
            headers=headers,
            json=payload,
            verify=False,
            timeout=15
        )
        
        if ar_resp.status_code == 200:
            api_reply = ar_resp.json()
            
            # CEK APAKAH ADA AGEN YANG GAGAL MENERIMA PERINTAH
            failed_items = api_reply.get('data', {}).get('failed_items', [])
            
            if failed_items:
                error_msg = failed_items[0].get('error', {}).get('message', 'Unknown Error')
                print(f"❌ [SOAR] API Gagal pada Agent! Alasan: {error_msg}")
            else:
                print(f"✅ [SOAR] Tembakan API Sukses Diterima Agen {agent_id}!")
        else:
            print(f"❌ [SOAR] Koneksi API Ditolak. Status: {ar_resp.status_code}")
            print(f"Detail Error: {ar_resp.text}")

    except Exception as e:
        print(f"❌ [SOAR] Kesalahan koneksi ke Wazuh API: {e}")

try:
    from main_scoring import get_threat_analysis
except ImportError:
    print("❌ Error Fatal: File 'main_scoring.py' tidak ditemukan!")
    print("   Pastikan kedua file ada di folder yang sama.")
    sys.exit(1)

LOG_FILE = "/var/ossec/logs/alerts/alerts.json"

IGNORE_EXT   = ('.part', '.tmp', '.crdownload', '.swp', '.temp')
IGNORE_PROTO = ('dns', 'dhcp', 'ntp', 'mdns', 'ssdp', 'arp')


# ─── FIM CORRELATION BUFFER ──────────────────────────────────────────────────
# Menyimpan hash dari FIM event, menunggu korelasi dengan Suricata fileinfo.
# Format: { sha256: { "path": str, "ts": datetime } }
#
# FIM event TIDAK langsung trigger scoring.
# Scoring baru jalan ketika Suricata mendeteksi hash yang sama (correlated),
# atau tetap jalan sebagai "suricata" saja jika hash tidak ada di buffer.

FIM_BUFFER: dict     = {}
FIM_BUFFER_TTL       = timedelta(minutes=10)
_buffer_lock         = threading.Lock()


def store_fim_hash(sha256: str, path: str, agent_id: str):
    """Simpan hash FIM ke buffer dan log ukurannya."""
    with _buffer_lock:
        FIM_BUFFER[sha256] = {
            "path": path,
            "agent_id": agent_id, #ID Agen
            "ts"  : datetime.now(),
        }
    print(f"    [Buffer] Hash disimpan: {sha256[:16]}... | size: {len(FIM_BUFFER)} entry")


def lookup_fim_hash(sha256: str) -> Optional[dict]:
    """
    Cek apakah hash dari Suricata ada di FIM buffer.
    Return entry dict jika ada dan belum expired, None jika tidak.
    """
    with _buffer_lock:
        entry = FIM_BUFFER.get(sha256)
        if not entry:
            return None
        if datetime.now() - entry["ts"] > FIM_BUFFER_TTL:
            del FIM_BUFFER[sha256]
            return None
        return entry


def _cleanup_worker():
    """
    Background daemon thread: bersihkan FIM_BUFFER dari entry expired
    setiap 2 menit. Mati otomatis saat main process berhenti (daemon=True).
    """
    while True:
        time.sleep(120)
        now = datetime.now()
        with _buffer_lock:
            expired = [k for k, v in FIM_BUFFER.items()
                       if now - v["ts"] > FIM_BUFFER_TTL]
            for k in expired:
                del FIM_BUFFER[k]
        if expired:
            print(f"[Buffer] Cleanup: {len(expired)} entry expired dihapus. "
                  f"Sisa: {len(FIM_BUFFER)} entry.")


# ─── LOG TAILER ──────────────────────────────────────────────────────────────

def follow_log(filepath: str):
    """Generator: tail -f behaviour."""
    if not os.path.exists(filepath):
        print(f"❌ File log tidak ditemukan: {filepath}")
        return
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            f.seek(0, 2)
            print(f"[*] Watchdog Aktif! Memantau: {filepath}")
            print("[*] Menunggu trigger (FIM / Suricata fileinfo)...")
            while True:
                line = f.readline()
                if not line:
                    time.sleep(0.1)
                    continue
                yield line
    except PermissionError:
        print("❌ Error: Permission Denied! Jalankan pakai 'sudo'.")
        sys.exit(1)


# ─── CORRELATION GATE ────────────────────────────────────────────────────────

def correlate_event(log: dict) -> Optional[dict]:
    """
    Routing event ke tiga kemungkinan:
      - None          → noise, abaikan
      - source=fim    → FIM detect, hash disimpan ke buffer, TIDAK trigger scoring
                        (return None supaya process_alert skip)
      - source=correlated → Suricata detect hash yang sama dengan FIM di buffer
                            → gabungkan: path dari FIM, src_ip dari Suricata
      - source=suricata   → Suricata detect tapi hash tidak ada di FIM buffer
                            → analisis IP saja seperti biasa
    """
    data_block = log.get('data', {})
    syscheck   = log.get('syscheck', {})
    agent_id   = log.get('agent', {}).get('id', '000')

    # ── JALUR FIM ──────────────────────────────────────────────────────────
    sha256_fim = syscheck.get('sha256_after')
    if sha256_fim:
        file_path = syscheck.get('path', 'Unknown')
        filename  = os.path.basename(file_path)

        if filename.lower().endswith(IGNORE_EXT):
            return None

        # Simpan ke buffer, TIDAK langsung trigger scoring.
        # Scoring akan jalan saat Suricata mendeteksi hash yang sama.
        store_fim_hash(sha256_fim, file_path, agent_id)
        return None   # ← sengaja None: FIM sendiri tidak trigger alert

    # ── JALUR SURICATA fileinfo ────────────────────────────────────────────
    event_type = data_block.get('event_type', '')
    app_proto  = data_block.get('app_proto', '').lower()
    fileinfo   = data_block.get('fileinfo', {})
    sha256_sur = fileinfo.get('sha256')

    if event_type == 'fileinfo' and sha256_sur:
        if app_proto in IGNORE_PROTO:
            return None

        file_path_sur = fileinfo.get('filename', 'Unknown')
        filename      = os.path.basename(file_path_sur)

        if filename.lower().endswith(IGNORE_EXT):
            return None

        src_ip  = data_block.get('src_ip',  '127.0.0.1')
        dest_ip = data_block.get('dest_ip', '127.0.0.1')

        # ── CEK KORELASI DENGAN FIM ────────────────────────────────────────
        fim_entry = lookup_fim_hash(sha256_sur)

        if fim_entry:
            # Hash cocok: gabungkan data FIM + Suricata
            print(f"    [KORELASI] Hash cocok!")
            print(f"               FIM path        : {fim_entry['path']}")
            print(f"               Suricata src_ip : {src_ip}")
            return {
                "source"   : "correlated",
                "file_hash": sha256_sur,
                "file_path": fim_entry["path"],   # path dari FIM
                "src_ip"   : src_ip,              # IP dari Suricata
                "dest_ip"  : dest_ip,
                "agent_id" : fim_entry["agent_id"]
            }
        else:
            # Suricata detect tapi FIM tidak/belum ada → analisis IP saja
            return {
                "source"   : "suricata",
                "file_hash": sha256_sur,
                "file_path": file_path_sur,
                "src_ip"   : src_ip,
                "dest_ip"  : dest_ip,
                "agent_id" : agent_id
            }

    # Semua event lain (port scan, DNS, HTTP tanpa file, dll) → NOISE
    return None


# ─── PROCESS ALERT ──────────────────────────────────────────────────────────

def process_alert(json_line: str) -> Optional[dict]:
    try:
        log = json.loads(json_line)
    except json.JSONDecodeError:
        return None

    ctx = correlate_event(log)
    if ctx is None:
        return None

    source    = ctx['source']
    file_hash = ctx['file_hash']
    file_path = ctx['file_path']
    src_ip    = ctx['src_ip']
    dest_ip   = ctx['dest_ip']
    agent_id  = ctx['agent_id']
    filename  = os.path.basename(file_path)

    print(f"\n[!] Trigger [{source.upper()}] → {filename}")
    if source == "fim":
        # Tidak akan sampai sini (FIM return None di correlate_event)
        print(f"    Hash : {file_hash}")
    elif source == "suricata":
        print(f"    File : {filename}  |  Src IP: {src_ip}")
    else:  # correlated
        print(f"    Hash : {file_hash[:24]}...")
        print(f"    Path : {file_path}")
        print(f"    Src IP (Suricata) : {src_ip}")

    try:
        analysis_result = get_threat_analysis(
            file_hash=file_hash,
            src_ip=src_ip,
            dest_ip=dest_ip,
            file_path=file_path,
            source=source,
        )

        # (BARU) Titipkan agent_id ke dictionary hasil analisis
        if analysis_result:
            analysis_result['agent_id'] = agent_id 
            
        analysis_result['target'] = {
                "file_hash": file_hash,    # Data asli dari korelasi FIM
                "filename" : filename,     # Data asli dari korelasi FIM
                "path"     : file_path,    # Data asli dari korelasi FIM
                "src_ip"   : src_ip,       # Data asli dari Suricata
                "dst_ip"   : dest_ip       # Data asli dari Suricata
            }
        
        return analysis_result
    except Exception as e:
        print(f"⚠️  Warning: Gagal analisis. Error: {e}")
        return None


# ─── MAIN ────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    # Jalankan background cleanup thread untuk FIM buffer
    cleanup_thread = threading.Thread(target=_cleanup_worker, daemon=True)
    cleanup_thread.start()
    print("[*] FIM buffer cleanup thread aktif (interval: 2 menit).")

    try:
        for new_line in follow_log(LOG_FILE):
            analysis_data = process_alert(new_line)

            if analysis_data:
                target  = analysis_data.get('target', {})
                scores  = analysis_data.get('scores', {})
                details = analysis_data.get('details', {})

                final_json = {
                    "timestamp": datetime.now().isoformat(),
                    "target": {
                        "agent_id": analysis_data.get('agent_id', '000'),
                        "file_hash": target.get('file_hash'),
                        "filename" : target.get('filename', 'unknown'),
                        "path"     : target.get('path'),
                        "src_ip"   : target.get('src_ip', '127.0.0.1'),
                        "dst_ip"   : target.get('dst_ip', '127.0.0.1'),
                    },
                    "scores": {
                        "final_score": scores.get('final_score', 0.0),
                        "status"     : scores.get('status', 'NORMAL'),
                        "severity"   : scores.get('severity', 'low'),
                    },
                    "details": details,
                }

                print(json.dumps(final_json, indent=2))

                # --- INSTANT SOAR MITIGATION ---
                if scores.get('status') == 'MALICIOUS':
                    file_hash = target.get('file_hash')
                    file_path = target.get('path')
                    
                    # PERBAIKAN DI SINI
                    agent_id  = analysis_data.get('agent_id', '000')
                    
                    filename  = target.get('filename', 'Unknown')
                    
                    # 1. Dokumentasikan ke CDB List (Silent)
                    append_to_cdb_silently(file_hash, f"{filename}")
                    
                    # 2. Eksekusi Pembasmian secara Real-Time via API
                    if file_path and agent_id != '000':
                        trigger_active_response(agent_id, file_path)
                # -------------------------------

                try:
                    with open("/var/log/cti_decision_results.log", "a") as f:
                        f.write(json.dumps(final_json) + "\n")
                except PermissionError:
                    print("❌ Error: Jalankan dengan 'sudo' untuk menulis log.")

    except KeyboardInterrupt:
        print("\n🛑 Watchdog dimatikan manual.")