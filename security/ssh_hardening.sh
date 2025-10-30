#!/bin/bash

################################################################################
# Script Name: ssh_hardening.sh
# Description: Усиление безопасности SSH сервера
# Author: Airat
# Version: 1.0
# Usage: sudo ./ssh_hardening.sh
# Warning: Создает бэкап конфига перед изменениями
################################################################################

# Проверка прав root
if [ "$EUID" -ne 0 ]; then
    echo "Error: This script must be run as root (use sudo)"
    exit 1
fi

# Цвета
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

SSH_CONFIG="/etc/ssh/sshd_config"
BACKUP_DIR="/root/ssh_backups"
TIMESTAMP=$(date +"%Y-%m-%d_%H%M%S")

# Функции логирования
log() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

# Заголовок
echo -e "${BLUE}=====================================${NC}"
echo -e "${BLUE}    SSH HARDENING SCRIPT${NC}"
echo -e "${BLUE}=====================================${NC}"
echo ""

# Создаем бэкап конфига
log "Creating backup of SSH config..."
mkdir -p "$BACKUP_DIR"
cp "$SSH_CONFIG" "${BACKUP_DIR}/sshd_config_${TIMESTAMP}.backup"
if [ $? -eq 0 ]; then
    success "Backup created: ${BACKUP_DIR}/sshd_config_${TIMESTAMP}.backup"
else
    error "Failed to create backup!"
    exit 1
fi

# Функция для безопасного изменения параметра
update_ssh_param() {
    local param=$1
    local value=$2
    local config=$SSH_CONFIG
    
    if grep -q "^${param}" "$config"; then
        sed -i "s/^${param}.*/${param} ${value}/" "$config"
        log "Updated: $param $value"
    elif grep -q "^#${param}" "$config"; then
        sed -i "s/^#${param}.*/${param} ${value}/" "$config"
        log "Enabled and set: $param $value"
    else
        echo "${param} ${value}" >> "$config"
        log "Added: $param $value"
    fi
}

echo ""
log "Applying security hardening..."
echo ""

# 1. Отключаем вход под root
log "Step 1: Disabling root login..."
update_ssh_param "PermitRootLogin" "no"
success "Root login disabled"

# 2. Отключаем вход по паролю (только ключи)
warning "Step 2: Disabling password authentication..."
warning "Make sure you have SSH keys configured before this!"
read -p "Disable password auth? (y/n): " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    update_ssh_param "PasswordAuthentication" "no"
    update_ssh_param "PubkeyAuthentication" "yes"
    success "Password authentication disabled"
else
    warning "Keeping password authentication enabled"
fi

# 3. Отключаем пустые пароли
log "Step 3: Disabling empty passwords..."
update_ssh_param "PermitEmptyPasswords" "no"
success "Empty passwords disabled"

# 4. Ограничиваем количество попыток аутентификации
log "Step 4: Limiting authentication attempts..."
update_ssh_param "MaxAuthTries" "3"
success "Max auth tries set to 3"

# 5. Устанавливаем таймаут
log "Step 5: Setting login timeout..."
update_ssh_param "LoginGraceTime" "60"
success "Login timeout set to 60 seconds"

# 6. Отключаем X11 Forwarding
log "Step 6: Disabling X11 forwarding..."
update_ssh_param "X11Forwarding" "no"
success "X11 forwarding disabled"

# 7. Используем только протокол 2
log "Step 7: Forcing SSH Protocol 2..."
update_ssh_param "Protocol" "2"
success "SSH Protocol 2 enforced"

# 8. Настраиваем клиентские keepalive
log "Step 8: Setting client keepalive..."
update_ssh_param "ClientAliveInterval" "300"
update_ssh_param "ClientAliveCountMax" "2"
success "Client keepalive configured"

# 9. Отключаем ненужные опции
log "Step 9: Disabling unnecessary options..."
update_ssh_param "PermitUserEnvironment" "no"
update_ssh_param "AllowTcpForwarding" "no"
update_ssh_param "AllowAgentForwarding" "no"
success "Unnecessary options disabled"

# 10. Ограничиваем пользователей (опционально)
echo ""
warning "Step 10: Limit SSH access to specific users?"
read -p "Enter allowed users (space-separated) or press Enter to skip: " allowed_users
if [ -n "$allowed_users" ]; then
    update_ssh_param "AllowUsers" "$allowed_users"
    success "SSH access limited to: $allowed_users"
else
    log "Skipping user restriction"
fi

# Проверяем конфигурацию
echo ""
log "Validating SSH configuration..."
sshd -t
if [ $? -eq 0 ]; then
    success "SSH configuration is valid!"
else
    error "SSH configuration has errors!"
    error "Restoring backup..."
    cp "${BACKUP_DIR}/sshd_config_${TIMESTAMP}.backup" "$SSH_CONFIG"
    exit 1
fi

# Перезапускаем SSH
echo ""
warning "SSH service needs to be restarted to apply changes"
warning "Make sure you have another session open before proceeding!"
read -p "Restart SSH now? (y/n): " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    log "Restarting SSH service..."
    systemctl restart sshd || systemctl restart ssh
    if [ $? -eq 0 ]; then
        success "SSH service restarted successfully!"
    else
        error "Failed to restart SSH service!"
        error "Please restart manually: systemctl restart sshd"
    fi
else
    warning "SSH service NOT restarted"
    warning "Changes will take effect after manual restart"
fi

# Итоговая информация
echo ""
echo -e "${BLUE}=====================================${NC}"
echo -e "${GREEN}SSH HARDENING COMPLETED!${NC}"
echo -e "${BLUE}=====================================${NC}"
echo ""
echo "Applied security measures:"
echo "  ✓ Root login disabled"
echo "  ✓ Password authentication: check manually"
echo "  ✓ Empty passwords disabled"
echo "  ✓ Max auth tries: 3"
echo "  ✓ Login timeout: 60 seconds"
echo "  ✓ X11 forwarding disabled"
echo "  ✓ Protocol 2 enforced"
echo "  ✓ Keepalive configured"
echo "  ✓ Unnecessary options disabled"
echo ""
echo "Backup location: ${BACKUP_DIR}/sshd_config_${TIMESTAMP}.backup"
echo ""
warning "IMPORTANT: Test SSH connection before closing this session!"
echo ""

