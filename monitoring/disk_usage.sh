#!/bin/bash

################################################################################
# Script Name: disk_usage.sh
# Description: Мониторинг использования дисков с предупреждениями
# Author: Airat
# Version: 1.0
# Usage: ./disk_usage.sh [warning_threshold] [critical_threshold]
################################################################################

# Цвета
RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
NC='\033[0m'

# Пороговые значения (в процентах)
WARNING_THRESHOLD=${1:-80}   # По умолчанию 80%
CRITICAL_THRESHOLD=${2:-90}  # По умолчанию 90%

# Заголовок
echo -e "${GREEN}=====================================${NC}"
echo -e "${GREEN}    DISK USAGE MONITOR${NC}"
echo -e "${GREEN}=====================================${NC}"
echo -e "Warning threshold : ${YELLOW}${WARNING_THRESHOLD}%${NC}"
echo -e "Critical threshold: ${RED}${CRITICAL_THRESHOLD}%${NC}"
echo ""

# Функция для проверки использования диска
check_disk() {
    local mount=$1
    local usage=$2
    local used=$3
    local total=$4
    
    # Убираем символ % из значения usage
    local usage_num=${usage%\%}
    
    # Определяем статус
    if [ "$usage_num" -ge "$CRITICAL_THRESHOLD" ]; then
        echo -e "${RED}[CRITICAL]${NC} $mount: $used / $total (${RED}$usage${NC})"
        return 2
    elif [ "$usage_num" -ge "$WARNING_THRESHOLD" ]; then
        echo -e "${YELLOW}[WARNING]${NC} $mount: $used / $total (${YELLOW}$usage${NC})"
        return 1
    else
        echo -e "${GREEN}[OK]${NC} $mount: $used / $total ($usage)"
        return 0
    fi
}

# Проверяем все диски
echo "Disk Usage Status:"
echo "-------------------------------------"

critical_count=0
warning_count=0

# Получаем информацию о дисках и проверяем каждый
while read line; do
    mount=$(echo "$line" | awk '{print $6}')
    usage=$(echo "$line" | awk '{print $5}')
    used=$(echo "$line" | awk '{print $3}')
    total=$(echo "$line" | awk '{print $2}')
    
    check_disk "$mount" "$usage" "$used" "$total"
    ret=$?
    
    if [ $ret -eq 2 ]; then
        ((critical_count++))
    elif [ $ret -eq 1 ]; then
        ((warning_count++))
    fi
    
done < <(df -h | grep -vE '^Filesystem|tmpfs|cdrom|loop')

# Итоговый статус
echo ""
echo "====================================="
echo "Summary:"
echo "-------------------------------------"
echo -e "Critical alerts: ${RED}$critical_count${NC}"
echo -e "Warning alerts : ${YELLOW}$warning_count${NC}"

if [ $critical_count -gt 0 ]; then
    echo -e "\n${RED}⚠ Action required! Critical disk usage detected!${NC}"
    exit 2
elif [ $warning_count -gt 0 ]; then
    echo -e "\n${YELLOW}⚠ Warning! Some disks are running low on space.${NC}"
    exit 1
else
    echo -e "\n${GREEN}✓ All disks are healthy!${NC}"
    exit 0
fi

