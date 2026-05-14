import time
import json
import os
import sys
from datetime import datetime

# --- PENTING: IMPORT LOGIKA SCORING ---
# Pastikan file main_scoring_json.py ada di satu folder dengan script ini
try:
    from main_scoring import get_threat_analysis
except ImportError:
    print("❌ Error Fatal: File 'main_scoring.py' tidak ditemukan!")
    print("   Pastikan kedua file ada di folder yang sama.")
    sys.exit(1)

# Lokasi Log Wazuh
LOG_FILE = "/tugas kuliah/2026_sem_8/weigth logic/log/alerts.json"

def follow_log(filepath):
    """
    Fungsi Generator: Bertindak seperti 'tail -f'.
    Hanya membaca baris baru yang ditulis Wazuh.
    """
    # Cek akses file
    if not os.path.exists(filepath):
        print(f"❌ File log tidak ditemukan: {filepath}")
        return

    try:
        with open(filepath, "r", encoding="utf-8") as f:
            # LOMPAT KE AKHIR FILE (Biar gak baca log masa lalu)
            f.seek(0, 2)
            
            print(f"✅ Watchdog Aktif! Memantau: {filepath}")
            print("⏳ Menunggu trigger FIM/Malware dari Wazuh...")

            while True:
                line = f.readline()
                if not line:
                    time.sleep(0.1) # Tidur 0.1 detik biar hemat CPU
                    continue
                yield line
    except PermissionError:
        print("❌ Error: Permission Denied! Jalankan pakai 'sudo'.")
        sys.exit(1)

def process_alert(json_line):
    """
    Fungsi Filter & Ekstrak Data
    """
    try:
        log = json.loads(json_line)
        
        # 1. CEK APAKAH ADA HASH? (Kunci Utama)
        # Kita cari di Syscheck (FIM) atau VirusTotal data
        syscheck = log.get('syscheck', {})
        vt_data  = log.get('data', {}).get('virustotal', {})
        
        file_hash = syscheck.get('sha256_after') or \
                    syscheck.get('md5_after') or \
                    vt_data.get('sha256')

        # Kalau gak ada hash, abaikan (Skip)
        if not file_hash:
            return None

        # 2. EKSTRAK FIELD LAINNYA
        data_block = log.get('data', {})
        
        # IP Address (Kalau FIM lokal, biasanya srcip kosong/lokal)
        src_ip = data_block.get('srcip', 'Localhost')
        dest_ip = data_block.get('dstip', 'Localhost')
        
        # Path & Filename
        file_path = syscheck.get('path') or "Unknown Path"
        filename = os.path.basename(file_path) if file_path else "unknown"

        # 3. KIRIM KE SISTEM PEMBOBOTAN (main_scoring_json.py)
        # Ini langkah paling krusial: Memanggil 4 Vendor CTI
        analysis_result = get_threat_analysis(
            file_hash=file_hash,
            src_ip=src_ip,
            dest_ip=dest_ip,
            file_path=file_path
        )
        
        return analysis_result

    except json.JSONDecodeError:
        return None
    except Exception as e:
        # Print error kecil buat debugging, tapi jangan stop loop
        print(f"⚠️ Warning: Gagal memproses baris log. Error: {e}")
        return None

# ==========================================
# MAIN EXECUTION
# ==========================================
if __name__ == "__main__":
    try:
        # Jalankan Loop Monitoring
        for new_line in follow_log(LOG_FILE):
            
            # Proses setiap baris baru
            hasil = process_alert(new_line)
            
            if hasil:
                # ---------------------------------------------------------
                # OUTPUT JSON BERSIH (SIAP DIKONSUMSI ELK/DASHBOARD)
                # ---------------------------------------------------------
                print(json.dumps(hasil, indent=4))
                
                # Opsional: Simpan ke file log khusus hasil analisis
                # with open("hasil_analisis_cti.json", "a") as f:
                #     f.write(json.dumps(hasil) + "\n")
                    
    except KeyboardInterrupt:
        print("\n🛑 Watchdog dimatikan manual.")