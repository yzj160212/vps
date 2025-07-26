#!/bin/bash

# Debian 12 VPS 设置脚本
# 优化版本，确保与 Debian 12 完全兼容

set -e  # 如果任何命令失败，立即退出

# 设置非交互式模式，避免安装过程中的交互提示
export DEBIAN_FRONTEND=noninteractive
export NEEDRESTART_MODE=a  # 自动重启服务，不询问

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# 日志变量
CONFIG_LIST=""

# 函数：打印彩色信息
print_info() {
    printf "${GREEN}[INFO]${NC} %s\n" "$1"
}

print_warning() {
    printf "${YELLOW}[WARNING]${NC} %s\n" "$1"
}

print_error() {
    printf "${RED}[ERROR]${NC} %s\n" "$1"
}

# 函数：检查命令执行状态
check_command() {
    if [ $? -eq 0 ]; then
        print_info "$1 成功"
        CONFIG_LIST+="✓ $1 成功\n"
    else
        print_error "$1 失败"
        exit 1
    fi
}

# 函数：检查是否为 root 用户
check_root() {
    if [[ $EUID -ne 0 ]]; then
        print_error "此脚本需要 root 权限运行"
        print_info "请使用: sudo $0"
        exit 1
    fi
}

# 函数：配置 APT 以避免交互式提示
configure_apt_noninteractive() {
    print_info "配置 APT 非交互式模式..."
    
    # 创建 APT 配置文件，自动处理配置文件冲突
    cat > /etc/apt/apt.conf.d/99-noninteractive << 'EOF'
// 非交互式配置，自动处理配置文件冲突
Dpkg::Options {
    "--force-confdef";
    "--force-confold";
}

// 禁用服务重启提示
DPkg::Post-Invoke { "systemctl daemon-reload || true"; };
EOF
    
    # 配置 needrestart 不询问重启服务
    if [ -f /etc/needrestart/needrestart.conf ]; then
        sed -i 's/#$nrconf{restart} = .*/\$nrconf{restart} = '\''a'\'';/' /etc/needrestart/needrestart.conf
    fi
    
    check_command "APT 非交互式配置"
}

# 函数：检查磁盘空间
check_disk_space() {
    print_info "检查磁盘空间..."
    
    local available_space=$(df / | awk 'NR==2 {print $4}')
    local available_gb=$((available_space / 1024 / 1024))
    
    print_info "可用磁盘空间: ${available_gb}GB"
    
    if [ "$available_gb" -lt 1 ]; then
        print_warning "磁盘空间不足 1GB，建议清理后再运行脚本"
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

# 函数：检查网络连接
check_network() {
    print_info "检查网络连接..."
    
    # 检查是否能访问 GitHub（使用更安全的方式）
    if ! timeout 10 wget --spider --quiet --no-check-certificate --user-agent="VPS-Setup-Script/1.0" https://raw.githubusercontent.com/yzj160212/vps/main/sshd_config; then
        print_warning "无法访问 GitHub，配置文件下载可能失败"
        print_info "脚本将使用备用配置继续执行"
    else
        print_info "网络连接正常"
    fi
}

# 函数：检查系统版本
check_debian_version() {
    if [ -f /etc/debian_version ]; then
        debian_version=$(cat /etc/debian_version)
        print_info "检测到 Debian 版本: $debian_version"
        
        # 检查是否为 Debian 12
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

# 函数：配置 SSH
configure_ssh() {
    local ssh_port="$1"
    local ssh_public_key="$2"
    
    print_info "正在配置 SSH..."
    
    # 备份原始配置
    local backup_file="/etc/ssh/sshd_config.backup.$(date +%Y%m%d_%H%M%S)"
    cp /etc/ssh/sshd_config "$backup_file"
    print_info "SSH 配置已备份到: $backup_file"
    
    # 下载 SSH 配置文件
    if wget -O /etc/ssh/sshd_config https://raw.githubusercontent.com/yzj160212/vps/main/sshd_config; then
        print_info "SSH 配置文件下载成功"
    else
        print_warning "SSH 配置文件下载失败，使用默认配置"
        # 如果下载失败，恢复备份并手动配置关键选项
        cp "$backup_file" /etc/ssh/sshd_config
        
        # 手动配置关键安全选项
        sed -i 's/^#PermitRootLogin.*/PermitRootLogin prohibit-password/' /etc/ssh/sshd_config
        sed -i 's/^#PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config
        sed -i 's/^#PubkeyAuthentication.*/PubkeyAuthentication yes/' /etc/ssh/sshd_config
        # 降低日志级别以减少日志量（低配置VPS优化）
        sed -i 's/^#*LogLevel.*/LogLevel INFO/' /etc/ssh/sshd_config
    fi
    
    # 修改 SSH 端口
    sed -i "s/^#*Port.*/Port $ssh_port/" /etc/ssh/sshd_config
    # 针对低配置VPS，降低日志级别（如果配置文件中是VERBOSE）
    sed -i 's/LogLevel VERBOSE/LogLevel INFO/' /etc/ssh/sshd_config
    check_command "SSH 端口修改为 $ssh_port"
    
    # 确保 root 用户的 .ssh 目录存在并设置权限
    mkdir -p /root/.ssh
    chmod 700 /root/.ssh
    
    # 确保 authorized_keys 文件存在并设置权限
    touch /root/.ssh/authorized_keys
    chmod 600 /root/.ssh/authorized_keys
    
    # 写入公钥（避免重复）
    # 使用更安全的方式检查和添加公钥
    local key_fingerprint=$(echo "$ssh_public_key" | awk '{print $2}')
    if ! grep -q "$key_fingerprint" /root/.ssh/authorized_keys 2>/dev/null; then
        echo "$ssh_public_key" >> /root/.ssh/authorized_keys
        print_info "SSH 公钥已添加"
    else
        print_info "SSH 公钥已存在，跳过添加"
    fi
    
    # 测试 SSH 配置
    if sshd -t; then
        print_info "SSH 配置语法检查通过"
    else
        print_error "SSH 配置语法错误，请检查"
        exit 1
    fi
}

# 函数：重启 SSH 服务
restart_ssh() {
    print_info "正在重启 SSH 服务..."
    
    # Debian 12 兼容的重启方式
    if systemctl restart ssh; then
        print_info "SSH 服务重启成功"
    elif systemctl restart sshd; then
        print_info "SSH 服务重启成功 (使用 sshd)"
    elif service ssh restart; then
        print_info "SSH 服务重启成功 (使用 service)"
    else
        print_error "SSH 服务重启失败"
        exit 1
    fi
    
    # 检查服务状态
    if systemctl is-active --quiet ssh || systemctl is-active --quiet sshd; then
        print_info "SSH 服务运行正常"
    else
        print_error "SSH 服务未正常运行"
        exit 1
    fi
}

# 函数：配置 fail2ban
configure_fail2ban() {
    local ssh_port="$1"
    
    print_info "正在安装和配置 fail2ban..."
    
    # 安装 fail2ban 和相关依赖
    apt install fail2ban iptables -y
    check_command "fail2ban 安装"
    
    # 创建本地配置目录
    mkdir -p /etc/fail2ban
    
    # 确保日志文件存在并配置大小限制
    touch /var/log/auth.log
    chmod 640 /var/log/auth.log
    chown root:adm /var/log/auth.log
    
    # 配置 rsyslog 限制日志大小（针对小VPS优化）
    cat > /etc/rsyslog.d/49-vps-optimize.conf << 'EOF'
# 针对小VPS的日志优化配置
# 限制 auth.log 大小，只记录关键信息
:programname, isequal, "sshd" /var/log/auth.log
& stop

# 减少其他不必要的日志
:msg, contains, "systemd-logind" stop
:msg, contains, "CRON" stop
EOF
    
    # 确保 rsyslog 服务运行
    systemctl enable rsyslog
    systemctl restart rsyslog
    
    # 下载你的自定义配置文件
    if wget -O /etc/fail2ban/jail.local https://raw.githubusercontent.com/yzj160212/vps/main/jail.local; then
        print_info "fail2ban 配置文件下载成功"
    else
        print_warning "fail2ban 配置文件下载失败，使用基础配置"
        # 创建基础的 jail.local 配置
        cat > /etc/fail2ban/jail.local << 'EOF'
[DEFAULT]
bantime = 604800
findtime = 600
maxretry = 3
backend = systemd
ignoreip = 127.0.0.1/8 ::1 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16

[sshd]
enabled = true
port = ssh
filter = sshd
logpath = /var/log/auth.log
maxretry = 3
bantime = 604800
findtime = 600
EOF
    fi
    
    # 可选：明确指定SSH端口（虽然port=ssh已经足够）
    # sed -i "s/port = ssh/port = $ssh_port/" /etc/fail2ban/jail.local
    
    # 测试 fail2ban 配置
    print_info "测试 fail2ban 配置..."
    if fail2ban-client -t; then
        print_info "fail2ban 配置测试通过"
    else
        print_warning "fail2ban 配置测试失败，尝试修复..."
        # 如果测试失败，使用最简配置
        cat > /etc/fail2ban/jail.local << 'EOF'
[DEFAULT]
bantime = 86400
findtime = 600
maxretry = 3
ignoreip = 127.0.0.1/8 ::1

[sshd]
enabled = true
port = ssh
filter = sshd
logpath = /var/log/auth.log
maxretry = 3
bantime = 86400
findtime = 600
EOF
    fi
    
    # 启动并启用 fail2ban 服务
    systemctl enable fail2ban
    systemctl start fail2ban
    
    # 等待服务完全启动
    sleep 5
    
    # 验证 fail2ban 是否正常运行
    local retry_count=0
    while [ $retry_count -lt 3 ]; do
        if systemctl is-active --quiet fail2ban; then
            print_info "fail2ban 服务运行正常"
            
            # 显示 fail2ban 状态
            print_info "fail2ban 状态:"
            if fail2ban-client status 2>/dev/null; then
                print_info "fail2ban 状态显示成功"
            else
                print_warning "fail2ban-client 暂时无法连接，服务正在启动中"
            fi
            break
        else
            retry_count=$((retry_count + 1))
            print_warning "fail2ban 启动中，等待重试... ($retry_count/3)"
            sleep 3
            systemctl restart fail2ban
        fi
    done
    
    if ! systemctl is-active --quiet fail2ban; then
        print_error "fail2ban 服务启动失败"
        print_info "尝试查看服务日志:"
        journalctl -u fail2ban --no-pager -l --lines=20
        print_warning "继续执行脚本，但 fail2ban 保护可能不可用"
        return 1
    else
        print_info "fail2ban 服务启动和启用 成功"
        CONFIG_LIST+="✓ fail2ban 服务启动和启用 成功\n"
    fi
    
    # 确保函数返回成功状态
    return 0
}

# 函数：配置日志轮转和清理（针对低配置VPS优化）
configure_logs() {
    print_info "正在配置日志管理（低配置VPS优化）..."
    
    # 配置 systemd-journald 限制日志大小
    mkdir -p /etc/systemd/journald.conf.d
    cat > /etc/systemd/journald.conf.d/size-limit.conf << 'EOF'
[Journal]
# 小VPS激进优化 - 限制日志总大小为 30MB
SystemMaxUse=30M
# 限制单个日志文件大小
SystemMaxFileSize=5M
# 保留时间 3 天
MaxRetentionSec=3d
# 压缩日志
Compress=yes
# 限制日志级别，减少不必要的日志
MaxLevelStore=info
# 保持持久化存储但限制大小
Storage=persistent
EOF
    
    # 重启 journald 服务应用配置
    systemctl restart systemd-journald
    check_command "systemd 日志配置优化"
    
    # 配置 logrotate 更频繁地轮转日志
    cat > /etc/logrotate.d/vps-optimize << 'EOF'
# 针对低配置VPS的日志轮转优化 - 更激进的清理
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
    
    # 立即清理旧日志
    print_info "清理现有大日志文件..."
    journalctl --vacuum-size=30M
    journalctl --vacuum-time=3d
    
    # 清理 apt 缓存
    apt clean
    apt autoclean
    
    # 添加定期清理的 cron 任务
    cat > /etc/cron.weekly/vps-cleanup << 'EOF'
#!/bin/bash
# 每周清理日志和缓存（小VPS激进优化）

# 清理 systemd 日志 - 更激进
journalctl --vacuum-size=20M
journalctl --vacuum-time=3d

# 清理 apt 缓存
apt clean
apt autoclean
apt autoremove -y

# 清理临时文件
find /tmp -type f -atime +3 -delete 2>/dev/null || true
find /var/tmp -type f -atime +3 -delete 2>/dev/null || true

# 清理旧的日志文件
find /var/log -name "*.log.*" -type f -mtime +7 -delete 2>/dev/null || true
find /var/log -name "*.gz" -type f -mtime +7 -delete 2>/dev/null || true

# 清理 fail2ban 数据库（如果太大）
if [ -f /var/lib/fail2ban/fail2ban.sqlite3 ]; then
    sqlite3_size=$(stat -c%s /var/lib/fail2ban/fail2ban.sqlite3 2>/dev/null || echo 0)
    if [ "$sqlite3_size" -gt 10485760 ]; then  # 如果大于10MB
        systemctl stop fail2ban
        rm -f /var/lib/fail2ban/fail2ban.sqlite3
        systemctl start fail2ban
    fi
fi

# 记录清理日志（限制大小）
echo "$(date): VPS cleanup completed, freed space: $(df -h / | awk 'NR==2{print $4}')" >> /var/log/vps-cleanup.log

# 严格限制清理日志大小
tail -n 20 /var/log/vps-cleanup.log > /tmp/cleanup.log && mv /tmp/cleanup.log /var/log/vps-cleanup.log
EOF
    
    chmod +x /etc/cron.weekly/vps-cleanup
    
    check_command "日志轮转和清理配置"
}

# 函数：配置防火墙
configure_firewall() {
    local ssh_port="$1"
    
    print_info "正在配置 UFW 防火墙..."
    
    # 安装 UFW
    apt install ufw -y
    check_command "UFW 安装"
    
    # 重置防火墙规则
    ufw --force reset
    
    # 设置默认策略
    ufw default deny incoming
    ufw default allow outgoing
    
    # 允许 SSH 端口
    ufw allow "$ssh_port"/tcp
    check_command "放行 SSH 端口 $ssh_port"
    
    # 允许 HTTP 和 HTTPS 端口
    ufw allow 80/tcp
    ufw allow 443/tcp
    check_command "放行 HTTP 和 HTTPS 端口"
    
    # 启用 UFW（非交互式）
    echo "y" | ufw enable
    check_command "UFW 启用"
    
    # 显示防火墙状态
    print_info "防火墙规则:"
    ufw status numbered
}

# 主函数
main() {
    print_info "开始执行 Debian 12 VPS 配置脚本..."
    
    # 检查权限和系统版本
    check_root
    check_debian_version
    check_disk_space
    check_network
    
    # 配置非交互式模式
    configure_apt_noninteractive
    
    # 更新系统
    print_info "正在更新系统..."
    apt update && apt upgrade -y
    check_command "系统更新"
    
    # 安装必要的工具
    print_info "正在安装必要工具..."
    apt install -y wget curl sudo systemd-timesyncd openssh-server rsyslog
    check_command "必要工具安装"
    
    # 确保 SSH 服务已启动并启用
    systemctl enable ssh
    systemctl start ssh
    
    # 更改时区
    print_info "正在设置时区为亚洲/上海..."
    timedatectl set-timezone Asia/Shanghai
    check_command "时区设置"
    
    # 获取用户输入 - SSH 端口
    while true; do
        printf "${GREEN}请输入自定义 SSH 端口号 (1024-65535，建议使用 10000-65535):${NC} "
        read -r SSH_PORT
        
        # 输入验证
        if [[ "$SSH_PORT" =~ ^[0-9]+$ ]] && [ "$SSH_PORT" -ge 1024 ] && [ "$SSH_PORT" -le 65535 ]; then
            # 检查端口是否被占用
            if netstat -tuln 2>/dev/null | grep -q ":$SSH_PORT " || ss -tuln 2>/dev/null | grep -q ":$SSH_PORT "; then
                print_warning "端口 $SSH_PORT 可能已被占用，请选择其他端口"
                continue
            fi
            print_info "SSH 端口设置为: $SSH_PORT"
            break
        else
            print_error "无效的端口号，请输入 1024-65535 之间的数字"
        fi
    done
    
    # 获取用户输入 - SSH 公钥
    while true; do
        printf "${GREEN}请输入您的 SSH 公钥:${NC} "
        read -r SSH_PUBLIC_KEY
        
        # 增强验证：检查SSH公钥格式
        if [[ -n "$SSH_PUBLIC_KEY" ]] && [[ "$SSH_PUBLIC_KEY" =~ ^ssh-(rsa|dss|ecdsa|ed25519)[[:space:]]+[A-Za-z0-9+/]+=*[[:space:]]*.*$ ]]; then
            # 检查公钥长度（避免过短的无效公钥）
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
    
    # 配置 SSH
    configure_ssh "$SSH_PORT" "$SSH_PUBLIC_KEY"
    
    # 配置 fail2ban
    if configure_fail2ban "$SSH_PORT"; then
        print_info "fail2ban 配置完成"
    else
        print_warning "fail2ban 配置可能有问题，但脚本继续执行"
    fi
    
    # 配置防火墙
    configure_firewall "$SSH_PORT"
    
    # 配置日志管理（低配置VPS优化）
    configure_logs
    
    # 重启 SSH 服务（在防火墙配置完成后）
    restart_ssh
    
    # 显示配置摘要
    print_info "=== 配置完成摘要 ==="
    printf "${CONFIG_LIST}"
    
    print_info "=== 重要信息 ==="
    print_warning "SSH 端口已修改为: $SSH_PORT"
    print_warning "请确保在断开连接前，用新端口测试 SSH 连接!"
    print_warning "测试命令: ssh -p $SSH_PORT root@$(hostname -I | awk '{print $1}')"
    print_warning "如果连接失败，可以通过 VPS 控制台恢复访问"
    
    print_info "=== 服务状态 ==="
    echo "SSH 服务状态:"
    systemctl status ssh --no-pager -l | head -3
    echo ""
    echo "fail2ban 服务状态:"
    systemctl status fail2ban --no-pager -l | head -3
    echo ""
    echo "UFW 防火墙状态:"
    ufw status
    echo ""
    echo "磁盘使用情况:"
    df -h / | grep -v Filesystem
    echo ""
    echo "内存使用情况:"
    free -h | grep -E "Mem|Swap"
    echo ""
    echo "日志文件占用情况:"
    echo "auth.log: $(du -h /var/log/auth.log 2>/dev/null | cut -f1 || echo '0K')"
    echo "fail2ban.log: $(du -h /var/log/fail2ban.log 2>/dev/null | cut -f1 || echo '0K')"
    echo "systemd journal: $(journalctl --disk-usage 2>/dev/null | grep -o '[0-9.]*[KMGT]' || echo '未知')"
    echo "总日志目录: $(du -sh /var/log 2>/dev/null | cut -f1 || echo '未知')"
    
    print_info "脚本执行完成！建议重启系统以确保所有配置生效。"
    read -p "是否立即重启系统？(y/N): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        print_info "系统将在 10 秒后重启..."
        sleep 10
        reboot
    else
        print_info "请稍后手动重启系统: sudo reboot"
    fi
}

# 执行主函数
main "$@"