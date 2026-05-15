# File: test_scoring.py
from main_scoring import get_threat_analysis

print("=== MEMULAI TES MODUL SKORING ===")
print("[*] Menyiapkan data dummy (EICAR Hash & IP Penyerang)...")

test_hash = "275a021bbfb6489e54d471899f7d1d516f1a8073baf37156ab4eec3fcb09e2d4" 
test_ip = "89.238.73.97"
test_dest = "127.0.0.1"
test_path = "/home/agent/Downloads/eicar.com.txt"

try:
    print("[*] Memanggil fungsi get_threat_analysis...")
    
    # Memanggil fungsi secara langsung
    hasil = get_threat_analysis(
        file_hash=test_hash, 
        src_ip=test_ip, 
        dest_ip=test_dest, 
        file_path=test_path, 
        source="suricata"
    )
    
    print("\n=== HASIL DARI MAIN SCORING ===")
    print(hasil)
    
except Exception as e:
    print(f"\n❌ TERJADI ERROR FATAL DI DALAM FUNGSI: {e}")