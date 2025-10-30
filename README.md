# 🔧 Linux Admin Toolkit

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Bash](https://img.shields.io/badge/bash-5.0+-green.svg)
![Python](https://img.shields.io/badge/python-3.8+-blue.svg)

Коллекция полезных скриптов и инструментов для ежедневных задач системного администратора Linux.

---

## 📖 Описание

**Linux Admin Toolkit** — это набор готовых скриптов для автоматизации рутинных задач системного администрирования. Все скрипты протестированы на Ubuntu 20.04+ и CentOS 7+.

### ✨ Особенности

- ✅ Готовые к использованию скрипты
- ✅ Подробные комментарии в коде
- ✅ Логирование всех операций
- ✅ Обработка ошибок
- ✅ Минимальные зависимости
- ✅ Документация для каждого скрипта

---

## 📂 Структура проекта

```
linux-admin-toolkit/
├── monitoring/          # Скрипты мониторинга
│   ├── system_info.sh      # Информация о системе
│   ├── disk_usage.sh       # Мониторинг дисков
│   ├── memory_check.sh     # Проверка памяти
│   └── service_monitor.sh  # Мониторинг сервисов
├── backup/              # Резервное копирование
│   ├── mysql_backup.sh     # Бэкап MySQL баз данных
│   ├── files_backup.sh     # Бэкап файлов и папок
│   └── backup_rotation.sh  # Ротация старых бэкапов
├── security/            # Безопасность
│   ├── firewall_setup.sh   # Настройка firewall (UFW/iptables)
│   ├── ssh_hardening.sh    # Усиление безопасности SSH
│   ├── fail2ban_setup.sh   # Установка и настройка Fail2Ban
│   └── ssl_check.sh        # Проверка SSL-сертификатов
├── automation/          # Автоматизация
│   ├── user_management.sh  # Управление пользователями
│   ├── log_cleanup.sh      # Очистка старых логов
│   └── updates_check.sh    # Проверка обновлений
└── network/             # Сетевые утилиты
    ├── port_scan.sh        # Сканирование открытых портов
    ├── bandwidth_check.sh  # Проверка использования bandwidth
    └── dns_check.sh        # Проверка DNS записей
```

---

## 🚀 Быстрый старт

### Требования

- Linux: Ubuntu 20.04+, CentOS 7+, Debian 10+
- Bash 5.0+
- Права sudo (для некоторых скриптов)

### Установка

```bash
# Клонируем репозиторий
git clone https://github.com/Airat71/linux-admin-toolkit.git

# Переходим в папку
cd linux-admin-toolkit

# Даем права на выполнение
chmod +x **/*.sh

# Готово! Можно использовать
```

---

## 📋 Использование

### Мониторинг системы

```bash
# Получить информацию о системе
./monitoring/system_info.sh

# Проверить использование дисков
./monitoring/disk_usage.sh

# Мониторинг памяти
./monitoring/memory_check.sh

# Проверить статус сервисов
./monitoring/service_monitor.sh nginx mysql
```

### Резервное копирование

```bash
# Бэкап MySQL базы данных
./backup/mysql_backup.sh database_name

# Бэкап директории
./backup/files_backup.sh /var/www/html /backup/

# Ротация старых бэкапов (оставить последние 7 дней)
./backup/backup_rotation.sh /backup/ 7
```

### Безопасность

```bash
# Настроить базовый firewall
sudo ./security/firewall_setup.sh

# Усилить безопасность SSH
sudo ./security/ssh_hardening.sh

# Установить и настроить Fail2Ban
sudo ./security/fail2ban_setup.sh

# Проверить SSL-сертификат
./security/ssl_check.sh example.com
```

### Автоматизация

```bash
# Создать нового пользователя с SSH-ключом
sudo ./automation/user_management.sh create username

# Очистить логи старше 30 дней
sudo ./automation/log_cleanup.sh 30

# Проверить доступные обновления
./automation/updates_check.sh
```

### Сетевые утилиты

```bash
# Сканировать открытые порты
./network/port_scan.sh

# Проверить использование bandwidth
./network/bandwidth_check.sh eth0

# Проверить DNS записи домена
./network/dns_check.sh example.com
```

---

## 🔥 Популярные сценарии использования

### Ежедневная проверка сервера

```bash
#!/bin/bash
# Ежедневный чек-лист

echo "=== System Info ==="
./monitoring/system_info.sh

echo "=== Disk Usage ==="
./monitoring/disk_usage.sh

echo "=== Memory Check ==="
./monitoring/memory_check.sh

echo "=== Updates Available ==="
./automation/updates_check.sh
```

### Настройка нового сервера

```bash
#!/bin/bash
# Базовая настройка нового сервера

# 1. Обновление системы
sudo apt update && sudo apt upgrade -y

# 2. Настройка firewall
sudo ./security/firewall_setup.sh

# 3. Усиление SSH
sudo ./security/ssh_hardening.sh

# 4. Установка Fail2Ban
sudo ./security/fail2ban_setup.sh

# 5. Настройка автоматических бэкапов
echo "0 2 * * * /path/to/backup/files_backup.sh" | sudo crontab -
```

---

## 📝 Документация скриптов

### monitoring/system_info.sh

**Назначение:** Выводит подробную информацию о системе

**Выходные данные:**
- Версия ОС
- Uptime
- Загрузка CPU
- Использование памяти
- Использование дисков
- Сетевые интерфейсы

**Пример вывода:**
```
====================================
    SYSTEM INFORMATION
====================================
Hostname: web-server-01
OS: Ubuntu 22.04 LTS
Kernel: 5.15.0-56-generic
Uptime: 15 days, 3 hours
Load Average: 0.52, 0.48, 0.45
CPU: Intel Xeon E5-2680 v4 (8 cores)
Memory: 7.2G / 16G (45%)
Disk /: 45G / 100G (45%)
```

---

### backup/mysql_backup.sh

**Назначение:** Создание резервной копии MySQL базы данных

**Использование:**
```bash
./backup/mysql_backup.sh <database_name> [backup_dir]
```

**Параметры:**
- `database_name` - имя базы данных (обязательно)
- `backup_dir` - директория для бэкапа (опционально, по умолчанию `/backup/mysql/`)

**Особенности:**
- Сжатие gzip
- Имя файла с датой и временем
- Проверка успешности бэкапа
- Логирование
- Автоматическое создание директории

**Пример:**
```bash
./backup/mysql_backup.sh wordpress /backup/db/
# Создаст файл: /backup/db/wordpress_2025-10-30_143052.sql.gz
```

---

### security/firewall_setup.sh

**Назначение:** Базовая настройка firewall

**Что делает:**
- Устанавливает UFW (если не установлен)
- Закрывает все входящие порты
- Открывает порты: 22 (SSH), 80 (HTTP), 443 (HTTPS)
- Включает firewall
- Показывает статус

**Использование:**
```bash
sudo ./security/firewall_setup.sh

# Открыть дополнительные порты
sudo ./security/firewall_setup.sh --custom-ports 3000,8080
```

---

## 🛠️ Настройка автоматического запуска (cron)

Добавьте нужные скрипты в crontab для автоматического выполнения:

```bash
# Редактируем crontab
crontab -e

# Примеры заданий:

# Бэкап MySQL каждый день в 2:00
0 2 * * * /path/to/backup/mysql_backup.sh mydatabase

# Проверка дисков каждый час
0 * * * * /path/to/monitoring/disk_usage.sh

# Ротация бэкапов раз в день в 3:00
0 3 * * * /path/to/backup/backup_rotation.sh /backup 7

# Очистка логов раз в неделю (воскресенье, 4:00)
0 4 * * 0 /path/to/automation/log_cleanup.sh 30
```

---

## ⚙️ Конфигурация

Некоторые скрипты поддерживают конфигурационные файлы. Создайте `.env` файл в корне проекта:

```bash
# Database settings
DB_USER=root
DB_PASSWORD=your_password
DB_HOST=localhost

# Backup settings
BACKUP_DIR=/backup
BACKUP_RETENTION_DAYS=7

# Notification settings (опционально)
ALERT_EMAIL=admin@example.com
SMTP_SERVER=smtp.gmail.com
```

---

## 📊 Логирование

Все скрипты логируют свою работу в `/var/log/admin-toolkit/`:

```bash
# Просмотр логов
tail -f /var/log/admin-toolkit/backup.log
tail -f /var/log/admin-toolkit/monitoring.log
tail -f /var/log/admin-toolkit/security.log
```

---

## 🤝 Содействие

Буду рад вашим предложениям и улучшениям!

1. Fork репозитория
2. Создайте ветку (`git checkout -b feature/amazing-script`)
3. Commit изменения (`git commit -am 'Add amazing script'`)
4. Push в ветку (`git push origin feature/amazing-script`)
5. Создайте Pull Request

---

## ⚠️ Дисклеймер

- Все скрипты предоставляются "как есть"
- Тестируйте на тестовых серверах перед использованием в production
- Делайте бэкапы перед запуском скриптов, изменяющих систему
- Автор не несет ответственности за возможные проблемы

---

## 📄 Лицензия

MIT License - см. файл [LICENSE](LICENSE)

---

## ✨ Автор

**Айрат** - Системный администратор

- GitHub: [@Airat71](https://github.com/Airat71)

---

## 🙏 Благодарности

- Яндекс.Практикум - за обучение системному администрированию
- Сообщество Linux - за вдохновение и поддержку

---

⭐ Если этот проект оказался полезен, поставьте звезду!

