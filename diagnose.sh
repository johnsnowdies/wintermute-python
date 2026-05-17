#!/bin/bash

# Скрипт для диагностики сетевых настроек до и после запуска VPN/Proxy.
# Использование: sudo ./diagnose.sh before  ИЛИ  sudo ./diagnose.sh after

PHASE=$1

if [ "$PHASE" != "before" ] && [ "$PHASE" != "after" ]; then
    echo "Usage: $0 {before|after}"
    exit 1
fi

OUTPUT_FILE="diag_${PHASE}.txt"

echo "=== Diagnosis started at $(date) for phase: $PHASE ===" > "$OUTPUT_FILE"
echo "Phase: $PHASE" >> "$OUTPUT_FILE"

echo -e "\n--- IP ADDRESSES ---" >> "$OUTPUT_FILE"
ip addr show >> "$OUTPUT_FILE" 2>&1

echo -e "\n--- IP ROUTES ---" >> "$OUTPUT_FILE"
ip route show >> "$OUTPUT_FILE" 2>&1

echo -e "\n--- DEFAULT GATEWAY CHECK (8.8.8.8) ---" >> "$OUTPUT_FILE"
ip route get 8.8.8.8 >> "$OUTPUT_FILE" 2>&1

echo -e "\n--- IP FORWARDING ---" >> "$OUTPUT_FILE"
sysctl net.ipv4.ip_forward >> "$OUTPUT_FILE" 2>&1

echo -e "\n--- IPTABLES (MANGLE) ---" >> "$OUTPUT_FILE"
iptables -t mangle -L -v -n >> "$OUTPUT_FILE" 2>&1

echo -e "\n--- IPTABLES (NAT) ---" >> "$OUTPUT_FILE"
iptables -t nat -L -v -n >> "$OUTPUT_FILE" 2>&1

echo -e "\n--- IPTABLES (FILTER) ---" >> "$OUTPUT_FILE"
iptables -L -v -n >> "$OUTPUT_FILE" 2>&1

echo -e "\n--- DNS CHECK (nslookup google.com) ---" >> "$OUTPUT_FILE"
nslookup google.com 2>&1 | head -n 10 >> "$OUTPUT_FILE"

echo -e "\n--- INTERNET CONNECTIVITY (ping 8.8.8.8) ---" >> "$OUTPUT_FILE"
ping -c 3 8.8.8.8 >> "$OUTPUT_FILE" 2>&1

echo "Diagnosis for $PHASE saved to $OUTPUT_FILE"
