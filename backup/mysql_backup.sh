#!/bin/bash

################################################################################
# Script Name: mysql_backup.sh
# Description: Создание резервной копии MySQL базы данных
# Author: Airat
# Version: 1.0
# Usage: ./mysql_backup.sh <database_name> [backup_dir] [mysql_user] [mysql_password]
################################################################################

# Цвета
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Параметры
DB_NAME=$1
BACKUP_DIR=${2:-"/backup/mysql"}
MYSQL_USER=${3:-"root"}
MYSQL_PASSWORD=$4

# Дата и время для имени файла
TIMESTAMP=$(date +"%Y-%m-%d_%H%M%S")
BACKUP_FILE="${BACKUP_DIR}/${DB_NAME}_${TIMESTAMP}.sql.gz"

# Проверка аргументов
if [ -z "$DB_NAME" ]; then
    echo -e "${RED}Error: Database name is required!${NC}"
    echo "Usage: $0 <database_name> [backup_dir] [mysql_user] [mysql_password]"
    echo "Example: $0 wordpress /backup/mysql root mypassword"
    exit 1
fi

# Логирование
log() {
    echo -e "${GREEN}[$(date '+%Y-%m-%d %H:%M:%S')]${NC} $1"
}

error() {
    echo -e "${RED}[$(date '+%Y-%m-%d %H:%M:%S')] ERROR:${NC} $1"
}

warning() {
    echo -e "${YELLOW}[$(date '+%Y-%m-%d %H:%M:%S')] WARNING:${NC} $1"
}

# Начало
log "==================================="
log "MySQL Backup Script Started"
log "==================================="
log "Database: $DB_NAME"
log "Backup directory: $BACKUP_DIR"
log "Backup file: $BACKUP_FILE"

# Создаем директорию для бэкапов если не существует
if [ ! -d "$BACKUP_DIR" ]; then
    log "Creating backup directory: $BACKUP_DIR"
    mkdir -p "$BACKUP_DIR"
    if [ $? -ne 0 ]; then
        error "Failed to create backup directory"
        exit 1
    fi
fi

# Проверяем доступность MySQL
log "Checking MySQL connection..."
if [ -n "$MYSQL_PASSWORD" ]; then
    mysql -u"$MYSQL_USER" -p"$MYSQL_PASSWORD" -e "SELECT 1" &>/dev/null
else
    mysql -u"$MYSQL_USER" -e "SELECT 1" &>/dev/null
fi

if [ $? -ne 0 ]; then
    error "Cannot connect to MySQL server"
    error "Please check your credentials"
    exit 1
fi
log "MySQL connection successful"

# Проверяем существование базы данных
log "Checking if database exists..."
if [ -n "$MYSQL_PASSWORD" ]; then
    DB_EXISTS=$(mysql -u"$MYSQL_USER" -p"$MYSQL_PASSWORD" -e "SHOW DATABASES LIKE '$DB_NAME'" | grep "$DB_NAME")
else
    DB_EXISTS=$(mysql -u"$MYSQL_USER" -e "SHOW DATABASES LIKE '$DB_NAME'" | grep "$DB_NAME")
fi

if [ -z "$DB_EXISTS" ]; then
    error "Database '$DB_NAME' does not exist"
    exit 1
fi
log "Database '$DB_NAME' found"

# Создаем бэкап
log "Starting backup..."
if [ -n "$MYSQL_PASSWORD" ]; then
    mysqldump -u"$MYSQL_USER" -p"$MYSQL_PASSWORD" \
        --single-transaction \
        --routines \
        --triggers \
        --events \
        "$DB_NAME" | gzip > "$BACKUP_FILE"
else
    mysqldump -u"$MYSQL_USER" \
        --single-transaction \
        --routines \
        --triggers \
        --events \
        "$DB_NAME" | gzip > "$BACKUP_FILE"
fi

# Проверяем успешность бэкапа
if [ $? -eq 0 ] && [ -f "$BACKUP_FILE" ]; then
    BACKUP_SIZE=$(du -h "$BACKUP_FILE" | cut -f1)
    log "Backup completed successfully!"
    log "Backup file: $BACKUP_FILE"
    log "Backup size: $BACKUP_SIZE"
    
    # Проверяем целостность сжатого файла
    log "Verifying backup integrity..."
    gzip -t "$BACKUP_FILE"
    if [ $? -eq 0 ]; then
        log "Backup integrity check passed"
    else
        error "Backup file is corrupted!"
        exit 1
    fi
    
    log "==================================="
    log "Backup completed successfully!"
    log "==================================="
    exit 0
else
    error "Backup failed!"
    exit 1
fi

