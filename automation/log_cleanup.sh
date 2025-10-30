#!/bin/bash

################################################################################
# Script Name: log_cleanup.sh
# Description: Очистка старых логов для освобождения места
# Author: Airat
# Version: 1.0
# Usage: sudo ./log_cleanup.sh [days]
# Example: sudo ./log_cleanup.sh 30  (удалит логи старше 30 дней)
################################################################################

# Цвета
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Параметры
DAYS=${1:-30}  # По умолчанию 30 дней
LOG_DIRS=(
    "/var/log"
    "/var/log/apache2"
    "/var/log/nginx"
    "/var/log/mysql"
)

# Проверка прав
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}Error: This script must be run as root (use sudo)${NC}"
    exit 1
fi

# Функции
log() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

# Заголовок
echo -e "${GREEN}=====================================${NC}"
echo -e "${GREEN}    LOG CLEANUP UTILITY${NC}"
echo -e "${GREEN}=====================================${NC}"
echo ""

log "Configuration:"
log "  Days to keep: $DAYS"
log "  Directories to clean: ${LOG_DIRS[@]}"
echo ""

# Подсчет места до очистки
log "Calculating current disk usage..."
BEFORE_SIZE=$(du -sh /var/log 2>/dev/null | cut -f1)
log "Current /var/log size: $BEFORE_SIZE"
echo ""

# Подтверждение
warning "This will delete log files older than $DAYS days"
read -p "Continue? (y/n): " -n 1 -r
echo ""
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    log "Operation cancelled by user"
    exit 0
fi

echo ""
log "Starting cleanup..."

# Счетчики
TOTAL_FILES=0
TOTAL_SIZE=0

# Поиск и удаление старых логов
for dir in "${LOG_DIRS[@]}"; do
    if [ -d "$dir" ]; then
        log "Cleaning: $dir"
        
        # Поиск файлов старше N дней
        while IFS= read -r -d '' file; do
            # Получаем размер файла
            size=$(stat -f%z "$file" 2>/dev/null || stat -c%s "$file" 2>/dev/null)
            
            # Удаляем файл
            if rm -f "$file" 2>/dev/null; then
                ((TOTAL_FILES++))
                ((TOTAL_SIZE+=size))
                log "  Deleted: $(basename "$file")"
            fi
        done < <(find "$dir" -type f -name "*.log.*" -mtime +$DAYS -print0 2>/dev/null)
        
        # Удаляем сжатые логи
        while IFS= read -r -d '' file; do
            size=$(stat -f%z "$file" 2>/dev/null || stat -c%s "$file" 2>/dev/null)
            if rm -f "$file" 2>/dev/null; then
                ((TOTAL_FILES++))
                ((TOTAL_SIZE+=size))
                log "  Deleted: $(basename "$file")"
            fi
        done < <(find "$dir" -type f \( -name "*.gz" -o -name "*.zip" \) -mtime +$DAYS -print0 2>/dev/null)
    fi
done

# Очистка journalctl логов (если systemd)
if command -v journalctl &> /dev/null; then
    log "Cleaning journalctl logs older than $DAYS days..."
    journalctl --vacuum-time=${DAYS}d &>/dev/null
fi

# Подсчет места после очистки
echo ""
log "Calculating new disk usage..."
AFTER_SIZE=$(du -sh /var/log 2>/dev/null | cut -f1)

# Конвертируем размер в читаемый формат
FREED_MB=$((TOTAL_SIZE / 1024 / 1024))

# Итог
echo ""
echo -e "${GREEN}=====================================${NC}"
echo -e "${GREEN}CLEANUP COMPLETED!${NC}"
echo -e "${GREEN}=====================================${NC}"
echo ""
echo "Statistics:"
echo "  Files deleted   : $TOTAL_FILES"
echo "  Space freed     : ${FREED_MB} MB"
echo "  /var/log before : $BEFORE_SIZE"
echo "  /var/log after  : $AFTER_SIZE"
echo ""
log "Cleanup completed successfully!"

