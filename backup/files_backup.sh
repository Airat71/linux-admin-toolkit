#!/bin/bash

################################################################################
# Script Name: files_backup.sh
# Description: Резервное копирование файлов и директорий
# Author: Airat
# Version: 1.0
# Usage: ./files_backup.sh <source_dir> <backup_dir>
# Example: ./files_backup.sh /var/www/html /backup/web
################################################################################

# Цвета
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Параметры
SOURCE_DIR=$1
BACKUP_DIR=$2
TIMESTAMP=$(date +"%Y-%m-%d_%H%M%S")
BACKUP_NAME="backup_${TIMESTAMP}.tar.gz"

# Проверка аргументов
if [ -z "$SOURCE_DIR" ] || [ -z "$BACKUP_DIR" ]; then
    echo -e "${RED}Error: Missing required arguments!${NC}"
    echo "Usage: $0 <source_dir> <backup_dir>"
    echo "Example: $0 /var/www/html /backup/web"
    exit 1
fi

# Проверка существования исходной директории
if [ ! -d "$SOURCE_DIR" ]; then
    echo -e "${RED}Error: Source directory does not exist: $SOURCE_DIR${NC}"
    exit 1
fi

# Функции логирования
log() {
    echo -e "${GREEN}[$(date '+%Y-%m-%d %H:%M:%S')]${NC} $1"
}

error() {
    echo -e "${RED}[$(date '+%Y-%m-%d %H:%M:%S')] ERROR:${NC} $1"
}

success() {
    echo -e "${GREEN}[$(date '+%Y-%m-%d %H:%M:%S')] SUCCESS:${NC} $1"
}

# Начало
log "======================================"
log "FILE BACKUP SCRIPT STARTED"
log "======================================"
log "Source: $SOURCE_DIR"
log "Destination: $BACKUP_DIR"
log "Backup file: $BACKUP_NAME"

# Создаем директорию для бэкапа
if [ ! -d "$BACKUP_DIR" ]; then
    log "Creating backup directory: $BACKUP_DIR"
    mkdir -p "$BACKUP_DIR"
    if [ $? -ne 0 ]; then
        error "Failed to create backup directory"
        exit 1
    fi
fi

# Полный путь к файлу бэкапа
BACKUP_FILE="${BACKUP_DIR}/${BACKUP_NAME}"

# Подсчет размера исходных данных
log "Calculating source size..."
SOURCE_SIZE=$(du -sh "$SOURCE_DIR" | cut -f1)
log "Source size: $SOURCE_SIZE"

# Создаем бэкап
log "Creating backup archive..."
log "This may take a while for large directories..."

tar -czf "$BACKUP_FILE" -C "$(dirname "$SOURCE_DIR")" "$(basename "$SOURCE_DIR")" 2>/dev/null

# Проверяем успешность
if [ $? -eq 0 ] && [ -f "$BACKUP_FILE" ]; then
    # Получаем размер бэкапа
    BACKUP_SIZE=$(du -h "$BACKUP_FILE" | cut -f1)
    
    success "Backup created successfully!"
    log "Backup file: $BACKUP_FILE"
    log "Backup size: $BACKUP_SIZE"
    log "Compression ratio: ~$(echo "scale=1; $(stat -f%z "$BACKUP_FILE" 2>/dev/null || stat -c%s "$BACKUP_FILE") * 100 / $(du -sb "$SOURCE_DIR" | cut -f1)" | bc)%"
    
    # Проверяем целостность архива
    log "Verifying backup integrity..."
    tar -tzf "$BACKUP_FILE" > /dev/null 2>&1
    if [ $? -eq 0 ]; then
        success "Backup integrity verified!"
    else
        error "Backup file is corrupted!"
        exit 1
    fi
    
    log "======================================"
    log "BACKUP COMPLETED SUCCESSFULLY!"
    log "======================================"
    exit 0
else
    error "Backup failed!"
    exit 1
fi

