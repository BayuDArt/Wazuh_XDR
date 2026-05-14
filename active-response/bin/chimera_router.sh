#!/bin/bash
# ========================================================
# CHIMERA ROUTER: Manager -> Agent via API (Versi JSON)
# ========================================================

LOG_FILE="/var/log/chimera_router_debug.log"
echo "======================================================" >> $LOG_FILE
echo "$(date) - [START] Router menerima request." >> $LOG_FILE

# 1. BACA INPUT JSON DARI WAZUH (STDIN)
read INPUT_JSON

# Cek apakah input kosong (untuk safety)
if [ -z "$INPUT_JSON" ]; then
    echo "$(date) - [ERROR] Tidak ada input JSON dari Wazuh." >> $LOG_FILE
    exit 1
fi

# Catat log mentah jika perlu (opsional, untuk memastikan JSON masuk)
# echo "RAW JSON: $INPUT_JSON" >> $LOG_FILE

# 2. EKSTRAK DATA MENGGUNAKAN JQ
TARGET_AGENT=$(echo "$INPUT_JSON" | jq -r .parameters.alert.agent.id)

# Mencari lokasi file:
# Karena log Anda berasal dari JSON custom (wazuh_monitor.py), letaknya ada di "target.path" di dalam log asli
TARGET_PATH=$(echo "$INPUT_JSON" | jq -r .parameters.alert.data.target.path)


echo "$(date) - [INFO] Extracted Agent ID: $TARGET_AGENT | Target Path: $TARGET_PATH" >> $LOG_FILE

# 3. VALIDASI DATA
if [ -z "$TARGET_AGENT" ] || [ "$TARGET_AGENT" == "null" ]; then
    echo "$(date) - [ERROR] Agent ID kosong/null. Menghentikan Router." >> $LOG_FILE
    exit 1
fi

if [ -z "$TARGET_PATH" ] || [ "$TARGET_PATH" == "null" ]; then
    echo "$(date) - [ERROR] Target Path kosong/null. Menghentikan Router." >> $LOG_FILE
    exit 1
fi

# 4. KONFIGURASI API MANAGER
MANAGER_IP="127.0.0.1"
API_USER="wazuh"
API_PASS="wazuh"
API_PORT="55000"

# Ambil Token API
TOKEN=$(curl -s -u $API_USER:$API_PASS -k -X GET "https://$MANAGER_IP:$API_PORT/security/user/authenticate" | jq -r .data.token)

if [ -z "$TOKEN" ] || [ "$TOKEN" == "null" ]; then
    echo "$(date) - [ERROR] Gagal mendapatkan Token API." >> $LOG_FILE
    exit 1
fi

# 5. KIRIM PERINTAH KE AGENT
PAYLOAD=$(cat <<EOF
{
  "command": "chimera_remove0",
  "arguments": ["$TARGET_PATH"]
}
EOF
)

RESPONSE=$(curl -s -k -X PUT "https://$MANAGER_IP:$API_PORT/active-response?agents_list=$TARGET_AGENT" \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    -d "$PAYLOAD")

echo "$(date) - [INFO] API Response: $RESPONSE" >> $LOG_FILE
echo "$(date) - [SUCCESS] Perintah hapus dikirim ke Agent $TARGET_AGENT" >> $LOG_FILE

exit 0