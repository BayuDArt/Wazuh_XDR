import json
import os

# GANTI DENGAN PATH LOG ASLI KAMU
LOG_FILE = "/tugas kuliah/2026_sem_8/weigth logic/log/alerts.json"

# Ini Data JSON EICAR yang kamu kasih tadi (Saya rapikan dikit formatnya)
log_data = {
    "timestamp": "2026-02-09T08:45:26.552+0000",
    "rule": {
        "level": 5,
        "description": "File added to the system.",
        "id": "554",
        "firedtimes": 1,
        "mail": False,
        "groups": ["ossec", "syscheck", "syscheck_entry_added", "syscheck_file"]
    },
    "agent": {
        "id": "002",
        "name": "agent1",
        "ip": "10.0.2.15"
    },
    "manager": {
        "name": "wazuh-server"
    },
    "id": "1770626726.72351",
    "full_log": "File '/home/chimera/Downloads/eicar.com.txt.1' added\nMode: realtime\n",
    "syscheck": {
        "path": "/home/chimera/Downloads/eicar.com.txt.1",
        "mode": "realtime",
        "size_after": "68",
        "perm_after": "rw-r--r--",
        "uid_after": "0",
        "gid_after": "0",
        "md5_after": "44d88612fea8a8f36de82e1278abb02f",
        "sha1_after": "3395856ce81f2b7382dee72602f798b642f14140",
        "sha256_after": "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",  # <-- INI HASH EICAR ASLI
        "uname_after": "root",
        "gname_after": "root",
        "mtime_after": "2025-01-03T15:29:17",
        "inode_after": 1317100,
        "event": "added"
    },
    "decoder": {
        "name": "syscheck_new_entry"
    },
    "location": "syscheck"
}

def inject_log():
    print(f"[*] Menembakkan Log EICAR ke {LOG_FILE}...")
    
    try:
        # Mode 'a' (Append) buat nambah di baris paling bawah
        with open(LOG_FILE, "a") as f:
            # json.dumps bikin jadi string JSON valid satu baris
            f.write(json.dumps(log_data) + "\n") 
            
        print("[+] Log BERHASIL ditembakkan!")
        print("[+] Cek terminal Watchdog sekarang!")
        
    except PermissionError:
        print("[-] Error: Permission Denied! Jalankan pakai 'sudo python3 injector.py'")
    except FileNotFoundError:
        print(f"[-] Error: File {LOG_FILE} tidak ditemukan. Cek path-nya!")

if __name__ == "__main__":
    inject_log()