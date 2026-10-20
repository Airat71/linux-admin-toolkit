# Linux Admin Toolkit

![License](https://img.shields.io/badge/license-MIT-blue.svg)

Seven Bash scripts for routine Linux server work: system info, disk usage, listening ports, file and MySQL backups, log cleanup, SSH hardening.

## Scripts

| Script | What it does | Usage |
|--------|--------------|-------|
| `monitoring/system_info.sh` | Prints OS, kernel, uptime, load, memory, disks, network interfaces | `./monitoring/system_info.sh` |
| `monitoring/disk_usage.sh` | Checks every mount against two thresholds (default 80% warning, 90% critical). Exit code 2 on critical | `./monitoring/disk_usage.sh [warning] [critical]` |
| `network/port_scan.sh` | Lists ports listening on this server | `./network/port_scan.sh [interface]` |
| `backup/files_backup.sh` | Packs a directory into a timestamped `.tar.gz` | `./backup/files_backup.sh <source_dir> <backup_dir>` |
| `backup/mysql_backup.sh` | Dumps one MySQL database to a timestamped gzip file | `./backup/mysql_backup.sh <database> [backup_dir] [user] [password]` |
| `automation/log_cleanup.sh` | Deletes log files older than N days in the standard log directories | `sudo ./automation/log_cleanup.sh [days]` (default 30) |
| `security/ssh_hardening.sh` | Changes `sshd_config` (for example `PermitRootLogin no`), saves a backup of the old config first | `sudo ./security/ssh_hardening.sh` |

```bash
git clone https://github.com/Airat71/linux-admin-toolkit.git
cd linux-admin-toolkit
chmod +x */*.sh
```

## What was checked

On 2026-10-20 I ran `system_info.sh`, `disk_usage.sh`, `port_scan.sh` and `files_backup.sh` in an Ubuntu 24.04 container. They run to the end. `mysql_backup.sh` was started without a MySQL server and stops with a clear error.

Not run: `log_cleanup.sh`, `ssh_hardening.sh` and a real MySQL backup. They change the system or need a database. Other distributions were not tested.

CI runs ShellCheck on every script (errors only).

## Warnings

- `ssh_hardening.sh` can lock you out of a server. Open a second SSH session and check that key login works before you run it.
- `log_cleanup.sh` deletes files. Run it on a test machine first.
- `mysql_backup.sh` takes the password as a command line argument, and other users can see it in the process list. Leave the password out and put the credentials in `~/.my.cnf` instead.

## License

MIT, see [LICENSE](LICENSE).
