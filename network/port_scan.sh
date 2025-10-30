#!/bin/bash

################################################################################
# Script Name: port_scan.sh
# Description: Сканирование открытых портов на локальном сервере
# Author: Airat
# Version: 1.0
# Usage: ./port_scan.sh [interface]
################################################################################

# Цвета
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Функции
log() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

# Заголовок
echo -e "${BLUE}=====================================${NC}"
echo -e "${BLUE}    PORT SCANNER${NC}"
echo -e "${BLUE}=====================================${NC}"
echo ""

# Получаем IP адрес
INTERFACE=${1:-$(ip route | grep default | awk '{print $5}' | head -1)}
IP_ADDR=$(ip addr show "$INTERFACE" 2>/dev/null | grep "inet " | awk '{print $2}' | cut -d/ -f1)

if [ -z "$IP_ADDR" ]; then
    IP_ADDR="127.0.0.1"
fi

log "Scanning host: $IP_ADDR"
log "Interface: $INTERFACE"
echo ""

# TCP порты
echo -e "${GREEN}TCP Listening Ports:${NC}"
echo "-------------------------------------"
echo -e "${YELLOW}PORT\tSTATE\tSERVICE${NC}"
echo "-------------------------------------"

# Используем ss или netstat
if command -v ss &> /dev/null; then
    ss -tlnp 2>/dev/null | grep LISTEN | awk '{print $4}' | grep -o '[0-9]*$' | sort -n | uniq | while read port; do
        service=$(grep -w "$port/tcp" /etc/services 2>/dev/null | awk '{print $1}' | head -1)
        [ -z "$service" ] && service="unknown"
        echo -e "${GREEN}$port\tOPEN\t$service${NC}"
    done
else
    netstat -tlnp 2>/dev/null | grep LISTEN | awk '{print $4}' | grep -o '[0-9]*$' | sort -n | uniq | while read port; do
        service=$(grep -w "$port/tcp" /etc/services 2>/dev/null | awk '{print $1}' | head -1)
        [ -z "$service" ] && service="unknown"
        echo -e "${GREEN}$port\tOPEN\t$service${NC}"
    done
fi

echo ""

# UDP порты
echo -e "${GREEN}UDP Listening Ports:${NC}"
echo "-------------------------------------"
echo -e "${YELLOW}PORT\tSTATE\tSERVICE${NC}"
echo "-------------------------------------"

if command -v ss &> /dev/null; then
    ss -ulnp 2>/dev/null | grep -v "State" | awk '{print $4}' | grep -o '[0-9]*$' | sort -n | uniq | while read port; do
        service=$(grep -w "$port/udp" /etc/services 2>/dev/null | awk '{print $1}' | head -1)
        [ -z "$service" ] && service="unknown"
        echo -e "${GREEN}$port\tOPEN\t$service${NC}"
    done
else
    netstat -ulnp 2>/dev/null | awk '{print $4}' | grep -o '[0-9]*$' | sort -n | uniq | while read port; do
        service=$(grep -w "$port/udp" /etc/services 2>/dev/null | awk '{print $1}' | head -1)
        [ -z "$service" ] && service="unknown"
        echo -e "${GREEN}$port\tOPEN\t$service${NC}"
    done
fi

echo ""
echo -e "${BLUE}=====================================${NC}"
echo -e "${GREEN}Scan completed!${NC}"
echo -e "${BLUE}=====================================${NC}"

