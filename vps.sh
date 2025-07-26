#!/bin/bash

# Debian 12 VPS 设置脚本

set -e

# 颜色定义
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly NC='\033[0m'

CONFIG_LIST=""
SSH_PORT=""
SSH_PUBLIC_KEY=""

cleanup_and_exit() {
    local exit_code="${1:-1}"
    rm -f /tmp/sshd_config.temp /tmp/jail.local.temp 2>/dev/null || true
    if [[ $exit_code -ne 0 ]]; then
        print_error "脚本执行失败，退出码: $exit_code"
    fi
    exit $exit_code
}

trap 'cleanup_and_exit 130' INT TERM

print_info()    { printf "${GREEN}[INFO]${NC} %s\n" "$1"; }
print_warning() { printf "${YELLOW}[WARNING]${NC} %s\n" "$1"; }
print_error()   { printf "${RED}[ERROR]${NC} %s\n" "$1"; }

safe_execute() {
    local cmd="$1"
    local desc="$2"
    local allow_fail="${3:-false}"
    if eval "$cmd"; then
        print_info "$desc 成功"
        CONFIG_LIST+="✓ $desc 成功\n"
        return 0
    else
        if [[ "$allow_fail" == "true" ]]; then
            print_warning "$desc 失败，但继续执行"
            return 1
        else
            print_error "$desc 失败"
            cleanup_and_exit 1
        fi
    fi
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        print_error "此脚本需要 root 权限运行"
        print_info "请使用: sudo $0"
        exit 1
    fi
}

configure_apt_noninteractive() {
    print_info "配置 APT 非交互式模式..."
    cat > /etc/apt/apt.conf.d/99-noninteractive << 'EOF'
// 非交互式配置，自动处理配置文件冲突
Dpkg::Options {
    "--force-confdef";
    "--force-confold";
}
// 禁用服务重启提示
DPkg::Post-Invoke { "systemctl daemon-reload || true"; };
EOF
    if [ -f /etc/needrestart/needrestart.conf ]; then
        sed -i 's/#$nrconf{restart} = .*/\$nrconf{restart} = '\''a'\'';/' /etc/needrestart/needrestart.conf
    fi
    safe_execute "true" "APT 非交互式配置"
}

check_disk_space() {
    print_info "检查磁盘空间..."
    local available_space=$(df / | awk 'NR==2 {print $4}')
    local available_gb=$((available_space / 1024 / 1024))
    print_info "可用磁盘空间: ${available_gb}GB"
    if [ "$available_gb" -lt 2 ]; then
        print_warning "磁盘空间不足 2GB，建议清理后再运行脚本"
        print_info "可以运行以下命令清理："
        print_info "sudo apt clean && sudo apt autoclean"
        print_info "sudo journalctl --vacuum-size=50M"
        read -p "是否继续执行？(y/N): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            exit 1
        fi
    fi
}

check_network() {
    print_info "检查网络连接..."
    if ! timeout 10 wget --spider --quiet --no-check-certificate --user-agent="VPS-Setup-Script/1.0" https://raw.githubusercontent.com/yzj160212/vps/main/sshd_config; then
        print_warning "无法访问 GitHub，配置文件下载可能失败"
        print_info "脚本将使用备用配置继续执行"
    else
        print_info "网络连接正常"
    fi
}

check_debian_version() {
    if [ -f /etc/debian_version ]; then
        debian_version=$(cat /etc/debian_version)
        print_info "检测到 Debian 版本: $debian_version"
        if [[ $debian_version == 12* ]] || grep -q "bookworm" /etc/os-release 2>/dev/null; then
            print_info "确认为 Debian 12，继续执行..."
        else
            print_warning "此脚本专为 Debian 12 优化，当前版本可能存在兼容性问题"
            read -p "是否继续执行？(y/N): " -n 1 -r
            echo
            if [[ ! $REPLY =~ ^[Yy]$ ]]; then
                exit 1
            fi
        fi
    else
        print_error "无法检测系统版本，请确认运行在 Debian 系统上"
        exit 1
    fi
}

create_ssh_config() {
    local ssh_port="$1"
    cat > /tmp/sshd_config.temp << EOF
# Debian 12 VPS 优化 SSH 配置
Port $ssh_port
Protocol 2
PermitRootLogin prohibit-password
PubkeyAuthentication yes
PasswordAuthentication no
ChallengeResponseAuthentication no
UsePAM yes
AllowUsers root
MaxAuthTries 3
MaxStartups 2:30:10
LoginGraceTime 30
ClientAliveInterval 300
ClientAliveCountMax 2
TCPKeepAlive yes
Compression yes
LogLevel INFO
SyslogFacility AUTH
X11Forwarding no
PrintMotd no
PrintLastLog no
AcceptEnv LANG LC_*
Subsystem sftp /usr/lib/openssh/sftp-server
EOF
}

configure_ssh() {
    local ssh_port="$1"
    local ssh_public_key="$2"
    print_info "正在配置 SSH..."
    local backup_file="/etc/ssh/sshd_config.backup.$(date +%Y%m%d_%H%M%S)"
    cp /etc/ssh/sshd_config "$backup_file"
    print_info "SSH 配置已备份到: $backup_file"
    if wget -O /tmp/sshd_config.temp https://raw.githubusercontent.com/yzj160212/vps/main/sshd_config 2>/dev/null; then
        print_info "SSH 配置文件下载成功"
        sed -i "s/^#*Port.*/Port $ssh_port/" /tmp/sshd_config.temp
        sed -i 's/LogLevel VERBOSE/LogLevel INFO/' /tmp/sshd_config.temp
    else
        print_warning "SSH 配置文件下载失败，使用内嵌配置"
        create_ssh_config "$ssh_port"
    fi
    if sshd -t -f /tmp/sshd_config.temp; then
        mv /tmp/sshd_config.temp /etc/ssh/sshd_config
        safe_execute "true" "SSH 配置文件应用"
    else
        print_error "SSH 配置验证失败，恢复备份"
        cp "$backup_file" /etc/ssh/sshd_config
        sed -i 's/^#PermitRootLogin.*/PermitRootLogin prohibit-password/' /etc/ssh/sshd_config
        sed -i 's/^#PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config
        sed -i 's/^#PubkeyAuthentication.*/PubkeyAuthentication yes/' /etc/ssh/sshd_config
        sed -i "s/^#*Port.*/Port $ssh_port/" /etc/ssh/sshd_config
        sed -i 's/^#*LogLevel.*/LogLevel INFO/' /etc/ssh/sshd_config
    fi
    safe_execute "true" "SSH 端口修改为 $ssh_port"
    mkdir -p /root/.ssh
    chmod 700 /root/.ssh
    touch /root/.ssh/authorized_keys
    chmod 600 /root/.ssh/authorized_keys
    if ! grep -qF "$ssh_public_key" /root/.ssh/authorized_keys 2>/dev/null; then
        echo "$ssh_public_key" >> /root/.ssh/authorized_keys
        print_info "SSH 公钥已添加"
    else
        print_info "SSH 公钥已存在，跳过添加"
    fi
    if sshd -t; then
        print_info "SSH 配置语法检查通过"
    else
        print_error "SSH 配置语法错误，请检查"
        cleanup_and_exit 1
    fi
}

restart_ssh() {
    print_info "正在重启 SSH 服务..."
    if systemctl restart ssh; then
        safe_execute "true" "SSH 服务重启"
    elif systemctl restart sshd; then
        safe_execute "true" "SSH 服务重启 (使用 sshd)"
    elif service ssh restart; then
        safe_execute "true" "SSH 服务重启 (使用 service)"
    else
        print_error "SSH 服务重启失败"
        cleanup_and_exit 1
    fi
    if systemctl is-active --quiet ssh || systemctl is-active --quiet sshd; then
        print_info "SSH 服务运行正常"
        if ss -tln | grep -q ":$SSH_PORT "; then
            safe_execute "true" "SSH 端口 $SSH_PORT 监听正常"
        else
            print_warning "SSH 端口监听检查异常"
        fi
    else
        print_error "SSH 服务未正常运行"
        cleanup_and_exit 1
    fi
}

create_fail2ban_config() {
    local ssh_port="$1"
    cat > /tmp/jail.local.temp << EOF
[DEFAULT]
bantime = 86400
findtime = 600
maxretry = 5
backend = systemd
ignoreip = 127.0.0.1/8 ::1

[sshd]
enabled = true
port = $ssh_port
filter = sshd
EOF
}

configure_fail2ban() {
    local ssh_port="$1"
    print_info "正在安装和配置 fail2ban..."
    safe_execute "apt install fail2ban iptables -y" "fail2ban 安装"
    mkdir -p /etc/fail2ban

    # 生成适合 Debian 12 的 jail.local（systemd 监控，不要 logpath）
    create_fail2ban_config "$ssh_port"

    # 下载并替换配置文件
    if wget -O /tmp/jail.local.temp https://raw.githubusercontent.com/yzj160212/vps/main/jail.local 2>/dev/null; then
        print_info "fail2ban 配置文件下载成功"
        # 自动修正 backend 或 logpath
        sed -i '/^logpath/d' /tmp/jail.local.temp
        sed -i 's/^backend = .*/backend = systemd/' /tmp/jail.local.temp
        sed -i "/^\[sshd\]/,/^\[/ s/port = .*/port = $ssh_port/" /tmp/jail.local.temp
    fi

    print_info "验证 fail2ban 配置..."
    if fail2ban-client -t 2>/dev/null; then
        mv /tmp/jail.local.temp /etc/fail2ban/jail.local
        print_info "fail2ban 配置验证完成"
    else
        print_warning "配置验证失败，使用最简配置"
        create_fail2ban_config "$ssh_port"
        mv /tmp/jail.local.temp /etc/fail2ban/jail.local
    fi

    systemctl enable fail2ban
    systemctl start fail2ban

    sleep 8

    # 只检查 jail 是否加载和过滤器是否正常，不做端口/日志判断
    local ssh_jail_status=$(fail2ban-client status sshd 2>/dev/null)
    if [[ -n "$ssh_jail_status" && "$ssh_jail_status" == *"Currently banned:"* && "$ssh_jail_status" == *"Filter"* ]]; then
        print_info "fail2ban SSH jail 状态正常"
        print_info "SSH jail 过滤器配置正常"
    else
        print_error "fail2ban SSH jail 状态异常"
        print_info "fail2ban SSH jail 状态输出如下："
        echo "$ssh_jail_status"
        cleanup_and_exit 1
    fi

    safe_execute "true" "fail2ban 服务启动和验证"
    print_info "fail2ban 服务验证通过"
    return 0
}

configure_logs() {
    print_info "正在配置日志管理（低配置VPS优化）..."
    mkdir -p /etc/systemd/journald.conf.d
    cat > /etc/systemd/journald.conf.d/size-limit.conf << 'EOF'
[Journal]
SystemMaxUse=30M
SystemMaxFileSize=5M
MaxRetentionSec=3d
Compress=yes
MaxLevelStore=info
Storage=persistent
EOF
    systemctl restart systemd-journald >/dev/null 2>&1
    safe_execute "true" "systemd 日志配置优化"
    cat > /etc/logrotate.d/vps-optimize << 'EOF'
/var/log/auth.log {
    daily
    rotate 2
    maxsize 5M
    compress
    delaycompress
    missingok
    notifempty
    create 640 root adm
    postrotate
        systemctl reload rsyslog > /dev/null 2>&1 || true
        systemctl reload fail2ban > /dev/null 2>&1 || true
    endscript
}
/var/log/fail2ban.log {
    daily
    rotate 2
    maxsize 2M
    compress
    delaycompress
    missingok
    notifempty
    create 640 root adm
    postrotate
        systemctl reload fail2ban > /dev/null 2>&1 || true
    endscript
}
/var/log/syslog {
    daily
    rotate 2
    compress
    delaycompress
    missingok
    notifempty
    create 640 syslog adm
    postrotate
        systemctl reload rsyslog > /dev/null 2>&1 || true
    endscript
}
/var/log/ufw.log {
    weekly
    rotate 2
    compress
    delaycompress
    missingok
    notifempty
    create 640 root adm
}
EOF
    print_info "清理现有大日志文件..."
    journalctl --vacuum-size=30M >/dev/null 2>&1
    journalctl --vacuum-time=3d >/dev/null 2>&1
    apt clean >/dev/null 2>&1
    apt autoclean >/dev/null 2>&1
    cat > /etc/cron.weekly/vps-cleanup << 'EOF'
#!/bin/bash
journalctl --vacuum-size=20M
journalctl --vacuum-time=3d
apt clean
apt autoclean
apt autoremove -y
find /tmp -type f -atime +3 -delete 2>/dev/null || true
find /var/tmp -type f -atime +3 -delete 2>/dev/null || true
find /var/log -name "*.log.*" -type f -mtime +7 -delete 2>/dev/null || true
find /var/log -name "*.gz" -type f -mtime +7 -delete 2>/dev/null || true
if [ -f /var/lib/fail2ban/fail2ban.sqlite3 ]; then
    sqlite3_size=$(stat -c%s /var/lib/fail2ban/fail2ban.sqlite3 2>/dev/null || echo 0)
    if [ "$sqlite3_size" -gt 10485760 ]; then
        systemctl stop fail2ban
        rm -f /var/lib/fail2ban/fail2ban.sqlite3
        systemctl start fail2ban
    fi
fi
echo "$(date): VPS cleanup completed, freed space: $(df -h / | awk 'NR==2{print $4}')" >> /var/log/vps-cleanup.log
tail -n 20 /var/log/vps-cleanup.log > /tmp/cleanup.log && mv /tmp/cleanup.log /var/log/vps-cleanup.log
EOF
    chmod +x /etc/cron.weekly/vps-cleanup
    safe_execute "true" "日志轮转和清理配置"
}

configure_firewall() {
    local ssh_port="$1"
    print_info "正在配置 UFW 防火墙..."
    if ! command -v ufw >/dev/null 2>&1; then
        safe_execute "apt install ufw -y" "UFW 安装"
        if ! command -v ufw >/dev/null 2>&1; then
            print_error "UFW 安装验证失败"
            cleanup_and_exit 1
        fi
        print_info "UFW 安装验证通过"
    else
        print_info "UFW 已安装"
    fi
    if ! systemctl is-enabled ufw >/dev/null 2>&1; then
        print_info "启用 UFW 服务..."
        systemctl enable ufw >/dev/null 2>&1
    fi
    safe_execute "ufw --force reset" "重置防火墙规则"
    safe_execute "ufw default deny incoming" "设置默认拒绝入站"
    safe_execute "ufw default allow outgoing" "设置默认允许出站"
    safe_execute "ufw allow $ssh_port/tcp" "放行 SSH 端口 $ssh_port"
    safe_execute "ufw allow 80/tcp" "放行 HTTP 端口"
    safe_execute "ufw allow 443/tcp" "放行 HTTPS 端口"
    safe_execute "echo 'y' | ufw enable" "UFW 启用"
    sleep 2
    print_info "验证防火墙状态..."
    local ufw_status=$(ufw status 2>/dev/null)
    if echo "$ufw_status" | grep -q "Status: active"; then
        print_info "防火墙已成功启用"
        local rules_ok=true
        if ! echo "$ufw_status" | grep -q "$ssh_port/tcp"; then
            print_error "SSH 端口 $ssh_port 规则未生效"
            rules_ok=false
        fi
        if ! echo "$ufw_status" | grep -q "80/tcp"; then
            print_error "HTTP 端口 80 规则未生效"
            rules_ok=false
        fi
        if ! echo "$ufw_status" | grep -q "443/tcp"; then
            print_error "HTTPS 端口 443 规则未生效"
            rules_ok=false
        fi
        if [ "$rules_ok" = true ]; then
            print_info "防火墙规则验证通过"
            print_info "当前防火墙规则:"
            ufw status numbered
            if iptables -L ufw-user-input 2>/dev/null | grep -q "$ssh_port"; then
                print_info "iptables 规则验证通过"
            else
                print_warning "iptables 规则可能未完全生效，但 UFW 状态正常"
            fi
            safe_execute "true" "防火墙配置和验证完成"
        else
            print_error "防火墙规则验证失败"
            print_info "当前防火墙状态:"
            echo "$ufw_status"
            print_info "iptables 规则:"
            iptables -L -n | head -20
            cleanup_and_exit 1
        fi
    else
        print_error "防火墙启用验证失败"
        print_info "UFW 状态输出:"
        echo "$ufw_status"
        print_info "UFW 服务状态:"
        systemctl status ufw --no-pager -l | head -10
        print_info "检查系统日志:"
        journalctl -u ufw --no-pager -l --lines=10
        cleanup_and_exit 1
    fi
}

get_user_input() {
    while true; do
        printf "${GREEN}请输入自定义 SSH 端口号 (1024-65535，建议使用 10000-65535):${NC} "
        read -r SSH_PORT
        if [[ "$SSH_PORT" =~ ^[0-9]+$ ]] && [ "$SSH_PORT" -ge 1024 ] && [ "$SSH_PORT" -le 65535 ]; then
            if ss -tuln 2>/dev/null | grep -q ":$SSH_PORT "; then
                print_warning "端口 $SSH_PORT 可能已被占用，请选择其他端口"
                continue
            fi
            print_info "SSH 端口设置为: $SSH_PORT"
            break
        else
            print_error "无效的端口号，请输入 1024-65535 之间的数字"
        fi
    done
    while true; do
        printf "${GREEN}请输入您的 SSH 公钥:${NC} "
        read -r SSH_PUBLIC_KEY
        if [[ -n "$SSH_PUBLIC_KEY" ]] && [[ "$SSH_PUBLIC_KEY" =~ ^ssh-(rsa|dss|ecdsa|ed25519)[[:space:]]+[A-Za-z0-9+/]+=*[[:space:]]*.*$ ]]; then
            local key_length=${#SSH_PUBLIC_KEY}
            if [ "$key_length" -gt 100 ] && [ "$key_length" -lt 4000 ]; then
                print_info "SSH 公钥验证通过"
                break
            else
                print_error "SSH 公钥长度异常，请检查公钥完整性"
            fi
        else
            print_error "SSH 公钥格式无效，公钥应该以 'ssh-rsa', 'ssh-ed25519' 等开头"
            print_info "示例: ssh-rsa AAAAB3NzaC1yc2EAAAA... user@host"
            print_info "或: ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA... user@host"
        fi
    done
}

main() {
    print_info "开始执行 Debian 12 VPS 配置脚本..."
    check_root
    check_debian_version
    check_disk_space
    check_network
    configure_apt_noninteractive
    print_info "正在更新系统..."
    safe_execute "apt update" "更新软件包列表"
    safe_execute "apt upgrade -y" "升级系统软件包"
    print_info "正在安装必要工具..."
    safe_execute "apt install -y wget curl sudo systemd-timesyncd openssh-server rsyslog" "必要工具安装"
    systemctl enable ssh >/dev/null 2>&1
    systemctl start ssh >/dev/null 2>&1
    print_info "正在设置时区为亚洲/上海..."
    safe_execute "timedatectl set-timezone Asia/Shanghai" "时区设置"
    get_user_input
    configure_ssh "$SSH_PORT" "$SSH_PUBLIC_KEY"
    print_info "配置 fail2ban（安全防护必需组件）..."
    if ! configure_fail2ban "$SSH_PORT"; then
        print_error "fail2ban 配置失败，这是关键安全组件"
        print_error "脚本无法继续执行，请检查系统状态"
        cleanup_and_exit 1
    fi
    print_info "fail2ban 配置并验证完成"
    configure_logs
    configure_firewall "$SSH_PORT"
    print_info "全部配置完成！"
    print_info "以下为本次配置过程概要："
    echo -e "$CONFIG_LIST"
    cleanup_and_exit 0
}

main "$@"
