#!/bin/bash

################################################################################
# Script Name: system_info.sh
# Description: Выводит подробную информацию о системе
# Author: Airat
# Version: 1.0
# Usage: ./system_info.sh
################################################################################

# Цвета для вывода
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Функция для вывода заголовка
print_header() {
    echo -e "${BLUE}====================================${NC}"
    echo -e "${BLUE}    SYSTEM INFORMATION${NC}"
    echo -e "${BLUE}====================================${NC}"
}

# Функция для вывода секции
print_section() {
    echo -e "\n${GREEN}$1${NC}"
    echo "------------------------------------"
}

# Функция для получения использования CPU
get_cpu_usage() {
    top -bn1 | grep "Cpu(s)" | awk '{print $2}' | cut -d'%' -f1
}

# Функция для получения использования памяти
get_memory_usage() {
    free -h | awk '/^Mem:/ {print $3 " / " $2 " (" int($3/$2*100) "%)"}'
}

# Функция для получения использования диска
get_disk_usage() {
    df -h / | awk 'NR==2 {print $3 " / " $2 " (" $5 ")"}'
}

# Главная функция
main() {
    print_header
    
    # Основная информация
    print_section "📋 BASIC INFO"
    echo "Hostname    : $(hostname)"
    echo "OS          : $(lsb_release -d 2>/dev/null | cut -f2 || cat /etc/os-release | grep "PRETTY_NAME" | cut -d'"' -f2)"
    echo "Kernel      : $(uname -r)"
    echo "Architecture: $(uname -m)"
    echo "Date        : $(date '+%Y-%m-%d %H:%M:%S')"
    echo "Uptime      : $(uptime -p | sed 's/up //')"
    
    # CPU информация
    print_section "💻 CPU INFO"
    echo "Model       : $(lscpu | grep "Model name" | cut -d':' -f2 | xargs)"
    echo "Cores       : $(nproc)"
    echo "Usage       : $(get_cpu_usage)%"
    echo "Load Average: $(uptime | awk -F'load average:' '{print $2}' | xargs)"
    
    # Память
    print_section "🧠 MEMORY INFO"
    echo "RAM Usage   : $(get_memory_usage)"
    
    # Диски
    print_section "💾 DISK INFO"
    echo "Root (/)    : $(get_disk_usage)"
    
    # Дополнительные диски
    echo ""
    df -h | grep -vE '^Filesystem|tmpfs|cdrom|loop' | awk '{print $6 " : " $3 "/" $2 " (" $5 ")"}'
    
    # Сеть
    print_section "🌐 NETWORK INFO"
    # Получаем активные сетевые интерфейсы
    ip -o link show | awk -F': ' '{print $2}' | grep -v lo | while read iface; do
        ipaddr=$(ip -4 addr show "$iface" 2>/dev/null | grep -oP '(?<=inet\s)\d+(\.\d+){3}')
        if [ -n "$ipaddr" ]; then
            echo "Interface   : $iface"
            echo "IP Address  : $ipaddr"
            echo ""
        fi
    done
    
    # Запущенные сервисы (только основные)
    print_section "🔧 RUNNING SERVICES"
    echo "Checking common services..."
    
    services=("nginx" "apache2" "mysql" "postgresql" "redis" "docker")
    for service in "${services[@]}"; do
        if systemctl is-active --quiet "$service" 2>/dev/null; then
            echo -e "${GREEN}✓${NC} $service - running"
        fi
    done
    
    # Активные соединения
    print_section "🔌 ACTIVE CONNECTIONS"
    echo "Established: $(netstat -an 2>/dev/null | grep ESTABLISHED | wc -l || ss -tan | grep ESTAB | wc -l)"
    echo "Listening  : $(netstat -an 2>/dev/null | grep LISTEN | wc -l || ss -tln | grep LISTEN | wc -l)"
    
    # Последние логины
    print_section "👤 RECENT LOGINS"
    last -n 5 | head -n 5
    
    echo -e "\n${BLUE}====================================${NC}"
    echo -e "${GREEN}Report completed successfully!${NC}"
    echo -e "${BLUE}====================================${NC}\n"
}

# Запуск
main

