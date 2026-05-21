#!/usr/bin/python3
import sys
import json
import os
from datetime import datetime

# ─── DOKUMENTASI VARIABEL ──────────────────────────────────────────────
LOG_FILE = "/var/ossec/logs/active-responses.log"

def write_log(message):
    """Mencetak log aktivitas skrip Active Response."""
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    with open(LOG_FILE, "a") as f:
        f.write(f"{timestamp} remove-threat: {message}\n")

def get_local_agent_id():
    """Membaca ID agen lokal dari file konfigurasi Wazuh (Safety Lock)."""
    try:
        if os.path.exists("/var/ossec/etc/client.keys"):
            with open("/var/ossec/etc/client.keys", "r") as f:
                return f.readline().split(" ")[0]
    except Exception:
        pass
    return "000" # Jika file tidak ada, asumsikan ini adalah mesin Manager

def main():
    write_log("Menerima pemicu Active Response. Skrip mulai berjalan...")
    
    try:
        # 1. BACA INPUT DARI MANAGER (Wazuh mengirimkan instruksi baris demi baris)
        for line in sys.stdin:
            input_data = line.strip()
            if not input_data:
                continue

            # 2. KONVERSI TEKS KE JSON OBJECT
            ar_data = json.loads(input_data)
            command = ar_data.get("command")

            # Wazuh mengirimkan ping 'check_keys' sebelum mengeksekusi
            if command == "check_keys":
                # Wajib dibalas agar Wazuh tahu skrip ini hidup
                print(json.dumps({"error": 0, "message": "Keys checked"}))
                sys.stdout.flush()
                continue

            # 3. PROSES PERINTAH EKSEKUSI UTAMA ('add')
            if command == "add":
                parameters = ar_data.get("parameters", {})
                alert = parameters.get("alert", {})
                rule_id = alert.get("rule", {}).get("id", "Unknown")
                
                write_log(f"INFO: Dipicu oleh Rule ID -> {rule_id}")
                
                target_path = None
                soar_target_id = None
                
                # Skenario A: Log berasal dari Wazuh Syscheck (FIM lokal murni - Rule 100002)
                syscheck_block = alert.get("syscheck", {})
                if "path" in syscheck_block:
                    target_path = syscheck_block.get("path")
                    
                # Skenario B: Log berasal dari kustom JSON SOAR kita (Broadcast - Rule 100500)
                else:
                    # PERBAIKAN: Menembus JSON "Double Inception" bawaan Wazuh
                    custom_data = alert.get("data", {}).get("data", {})
                    target_path = custom_data.get("target", {}).get("path")
                    soar_target_id = custom_data.get("target", {}).get("agent_id")
                
                # 4. CHIMERA SAFETY LOCK (Hanya untuk skenario Broadcast SOAR)
                if soar_target_id:
                    my_agent_id = get_local_agent_id()
                    if soar_target_id != my_agent_id:
                        write_log(f"INFO: Abaikan perintah. Target adalah Agen {soar_target_id}, tapi saya Agen {my_agent_id}.")
                        # Beritahu Manager bahwa kita sukses mengabaikannya dengan aman
                        print(json.dumps({"error": 0, "message": "Ignored, broadcast targeted another agent"}))
                        sys.stdout.flush()
                        return # Hentikan skrip sampai di sini
                
                # 5. PROSES PENGHAPUSAN FILE
                if target_path:
                    write_log(f"Target ditemukan. Bersiap menghapus file: {target_path}")
                    
                    if os.path.exists(target_path):
                        os.remove(target_path)
                        write_log(f"SUKSES: Ancaman pada {target_path} telah dihancurkan!")
                    else:
                        write_log(f"INFO: File {target_path} tidak ditemukan (Mungkin sudah terhapus FIM).")
                else:
                    write_log("ERROR: Variabel 'path' tidak ditemukan di dalam log JSON.")
                    write_log(f"DEBUG Dump JSON: {input_data}")

                # Wajib membalas sukses ke Wazuh Manager di akhir eksekusi
                print(json.dumps({"error": 0, "message": "Active response completed"}))
                sys.stdout.flush()
                return # Keluar dengan aman

    except json.JSONDecodeError:
        write_log("ERROR: Format input bukan JSON yang valid.")
    except Exception as e:
        write_log(f"ERROR FATAL: {str(e)}")

if __name__ == "__main__":
    main()