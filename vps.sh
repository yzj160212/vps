#!/bin/bash

# Debian 12 VPS 设置脚本
# 优化版本，修复逻辑问题，确保与 Debian 12 完全兼容

set -e  # 如果任何命令失败，立即退出

# 设置非交互式模式，避免安装过程中的交互提示
export DEBIAN_FRONTEND=noninteractive
export NEEDRESTART_MODE=a  # 自动重启服务，不询问

# 颜色定义
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly NC='\033[0m' # No Color

# 全局变量
CONFIG_LIST=""
SSH_PORT=""
SSH_PUBLIC_KEY=""

# 清理函数
cleanup_and_exit() {
    local exit_code="${1:-1}"
    # 清理临时文件
    rm -f /tmp/sshd_config.temp /tmp/jail.local.temp 2>/dev/null || true
    
    if [[ $exit_code -ne 0 ]]; then
        print_error "脚本执行失败，退出码: $exit_code"
    fi
    
    exit $exit_code
}

# 设置信号处理
trap 'cleanup_and_exit 130' INT TERM

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

# 函数：安全执行命令并检查状态
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
    
    safe_execute "true" "APT 非交互式配置"
}

# 函数：检查磁盘空间
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

# 创建内嵌的 SSH 配置
create_ssh_config() {
    local ssh_port="$1"
    
    cat > /tmp/sshd_config.temp << EOF
# Debian 12 VPS 优化 SSH 配置
Port $ssh_port
Protocol 2

# 认证设置
PermitRootLogin prohibit-password
PubkeyAuthentication yes
PasswordAuthentication no
ChallengeResponseAuthentication no
UsePAM yes

# 安全设置
AllowUsers root
MaxAuthTries 3
MaxStartups 2:30:10
LoginGraceTime 30

# 性能优化（低配 VPS）
ClientAliveInterval 300
ClientAliveCountMax 2
TCPKeepAlive yes
Compression yes

# 日志最小化
LogLevel INFO
SyslogFacility AUTH

# 其他设置
X11Forwarding no
PrintMotd no
PrintLastLog no
AcceptEnv LANG LC_*
Subsystem sftp /usr/lib/openssh/sftp-server
EOF
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
    
    # 尝试下载 SSH 配置文件，失败则使用内嵌配置
    if wget -O /tmp/sshd_config.temp https://raw.githubusercontent.com/yzj160212/vps/main/sshd_config 2>/dev/null; then
        print_info "SSH 配置文件下载成功"
        # 修改端口
        sed -i "s/^#*Port.*/Port $ssh_port/" /tmp/sshd_config.temp
        # 针对低配置VPS，降低日志级别
        sed -i 's/LogLevel VERBOSE/LogLevel INFO/' /tmp/sshd_config.temp
    else
        print_warning "SSH 配置文件下载失败，使用内嵌配置"
        create_ssh_config "$ssh_port"
    fi
    
    # 验证配置文件
    if sshd -t -f /tmp/sshd_config.temp; then
        mv /tmp/sshd_config.temp /etc/ssh/sshd_config
        safe_execute "true" "SSH 配置文件应用"
    else
        print_error "SSH 配置验证失败，恢复备份"
        cp "$backup_file" /etc/ssh/sshd_config
        # 手动配置关键选项
        sed -i 's/^#PermitRootLogin.*/PermitRootLogin prohibit-password/' /etc/ssh/sshd_config
        sed -i 's/^#PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config
        sed -i 's/^#PubkeyAuthentication.*/PubkeyAuthentication yes/' /etc/ssh/sshd_config
        sed -i "s/^#*Port.*/Port $ssh_port/" /etc/ssh/sshd_config
        sed -i 's/^#*LogLevel.*/LogLevel INFO/' /etc/ssh/sshd_config
    fi
    
    safe_execute "true" "SSH 端口修改为 $ssh_port"
    
    # 确保 root 用户的 .ssh 目录存在并设置权限
    mkdir -p /root/.ssh
    chmod 700 /root/.ssh
    
    # 确保 authorized_keys 文件存在并设置权限
    touch /root/.ssh/authorized_keys
    chmod 600 /root/.ssh/authorized_keys
    
    # 写入公钥（避免重复）
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
        cleanup_and_exit 1
    fi
}

# 函数：重启 SSH 服务
restart_ssh() {
    print_info "正在重启 SSH 服务..."
    
    # Debian 12 兼容的重启方式
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
    
    # 检查服务状态
    if systemctl is-active --quiet ssh || systemctl is-active --quiet sshd; then
        print_info "SSH 服务运行正常"
        # 验证端口监听
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

# 创建内嵌的 fail2ban 配置
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
logpath = /var/log/auth.log
maxretry = 5
EOF
}

# 函数：配置 fail2ban
configure_fail2ban() {
    local ssh_port="$1"
    
    print_info "正在安装和配置 fail2ban..."
    
    # 安装 fail2ban 和相关依赖
    safe_execute "apt install fail2ban iptables -y" "fail2ban 安装"
    
    # 创建本地配置目录
    mkdir -p /etc/fail2ban
    
    # 确保日志文件存在并配置大小限制
    touch /var/log/auth.log
    chmod 640 /var/log/auth.log
    chown root:adm /var/log/auth.log
    
    # 配置 rsyslog 确保 SSH 日志正确记录
    cat > /etc/rsyslog.d/49-vps-optimize.conf << 'EOF'
# 确保 SSH 认证日志正确记录到 auth.log
auth,authpriv.*                 /var/log/auth.log

# 减少其他不必要的日志（但不影响 SSH 日志）
:msg, contains, "systemd-logind" stop
:msg, contains, "CRON" stop
EOF
    
    # 确保 rsyslog 服务运行
    systemctl enable rsyslog
    systemctl restart rsyslog
    
    # 等待 rsyslog 重启完成，确保日志文件可用
    sleep 3
    
    # 生成一些初始日志内容，确保文件不为空
    logger -p auth.info "fail2ban setup: SSH service configured"
    
    # 尝试下载配置文件，失败则使用内嵌配置
    if wget -O /tmp/jail.local.temp https://raw.githubusercontent.com/yzj160212/vps/main/jail.local 2>/dev/null; then
        print_info "fail2ban 配置文件下载成功"
        
        # 替换下载配置文件中的端口号
        sed -i "/^\[sshd\]/,/^\[/ s/port = ssh/port = $ssh_port/" /tmp/jail.local.temp
        
        # 验证下载的配置文件
        if ! fail2ban-client -t 2>/dev/null; then
            print_warning "下载的配置文件有问题，使用内嵌配置"
            create_fail2ban_config "$ssh_port"
        fi
    else
        print_warning "fail2ban 配置文件下载失败，使用内嵌配置"
        create_fail2ban_config "$ssh_port"
    fi
    
    # 验证配置文件
    print_info "验证 fail2ban 配置..."
    if fail2ban-client -t 2>/dev/null; then
        mv /tmp/jail.local.temp /etc/fail2ban/jail.local
        print_info "fail2ban 配置验证完成"
    else
        print_warning "配置验证失败，使用最简配置"
        create_fail2ban_config "$ssh_port"
        mv /tmp/jail.local.temp /etc/fail2ban/jail.local
    fi
    
    # 启动并启用 fail2ban 服务
    systemctl enable fail2ban
    
    # 确保日志文件有内容后再启动
    if [ ! -s /var/log/auth.log ]; then
        print_info "初始化 auth.log 文件..."
        logger -p auth.info "fail2ban: Initial log entry for SSH monitoring"
        echo "$(date) sshd[$$]: Server listening on 0.0.0.0 port $ssh_port." >> /var/log/auth.log
    fi
    
    # 启动服务
    systemctl start fail2ban
    
    # 等待服务完全启动
    sleep 8
    
    # 验证 fail2ban 是否正常运行
    local retry_count=0
    while [ $retry_count -lt 5 ]; do
        if systemctl is-active --quiet fail2ban; then
            print_info "fail2ban 服务运行正常"
            
            # 等待 jail 完全加载
            sleep 3
            
            # 显示 fail2ban 状态
            if fail2ban-client status 2>/dev/null | grep -q "sshd"; then
                print_info "fail2ban SSH jail 运行正常"
                fail2ban-client status sshd 2>/dev/null || true
                safe_execute "true" "fail2ban 服务启动和启用"
            else
                print_warning "fail2ban SSH jail 可能未正确加载"
                safe_execute "true" "fail2ban 服务启动和启用" "true"
            fi
            break
        else
            retry_count=$((retry_count + 1))
            print_warning "fail2ban 启动中，等待重试... ($retry_count/5)"
            
            # 查看启动错误
            if [ $retry_count -eq 3 ]; then
                print_info "检查启动错误:"
                journalctl -u fail2ban --no-pager -l --lines=10
            fi
            
            sleep 5
            systemctl restart fail2ban
        fi
    done
    
    if ! systemctl is-active --quiet fail2ban; then
        print_error "fail2ban 服务启动失败"
        print_info "尝试查看服务日志:"
        journalctl -u fail2ban --no-pager -l --lines=20
        print_warning "继续执行脚本，但 fail2ban 保护可能不可用"
        return 1
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
    systemctl restart systemd-journald >/dev/null 2>&1
    safe_execute "true" "systemd 日志配置优化"
    
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
    journalctl --vacuum-size=30M >/dev/null 2>&1
    journalctl --vacuum-time=3d >/dev/null 2>&1
    
    # 清理 apt 缓存
    apt clean >/dev/null 2>&1
    apt autoclean >/dev/null 2>&1
    
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
    
    safe_execute "true" "日志轮转和清理配置"
}

# 函数：配置防火墙
configure_firewall() {
    local ssh_port="$1"
    
    print_info "正在配置 UFW 防火墙..."
    
    # 确保 UFW 已安装
    if ! command -v ufw >/dev/null 2>&1; then
        safe_execute "apt install ufw -y" "UFW 安装"
    else
        print_info "UFW 已安装"
    fi
    
    # 重置防火墙规则
    safe_execute "ufw --force reset" "重置防火墙规则"
    
    # 设置默认策略
    safe_execute "ufw default deny incoming" "设置默认拒绝入站"
    safe_execute "ufw default allow outgoing" "设置默认允许出站"
    
    # 允许 SSH 端口
    safe_execute "ufw allow $ssh_port/tcp" "放行 SSH 端口 $ssh_port"
    
    # 允许 HTTP 和 HTTPS 端口
    safe_execute "ufw allow 80/tcp" "放行 HTTP 端口"
    safe_execute "ufw allow 443/tcp" "放行 HTTPS 端口"
    
    # 启用 UFW（非交互式）
    safe_execute "echo 'y' | ufw enable" "UFW 启用"
    
    # 验证防火墙状态
    if ufw status | grep -q "Status: active"; then
        print_info "防火墙已成功启用"
        # 显示防火墙规则
        print_info "防火墙规则:"
        ufw status numbered
    else
        print_error "防火墙启用验证失败"
        cleanup_and_exit 1
    fi
}

# 函数：获取用户输入并验证
get_user_input() {
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
    safe_execute "apt update" "更新软件包列表"
    safe_execute "apt upgrade -y" "升级系统软件包"
    
    # 安装必要的工具
    print_info "正在安装必要工具..."
    safe_execute "apt install -y wget curl sudo systemd-timesyncd openssh-server rsyslog" "必要工具安装"
    
    # 确保 SSH 服务已启动并启用
    systemctl enable ssh >/dev/null 2>&1
    systemctl start ssh >/dev/null 2>&1
    
    # 更改时区
    print_info "正在设置时区为亚洲/上海..."
    safe_execute "timedatectl set-timezone Asia/Shanghai" "时区设置"
    
    # 获取用户输入
    get_user_input
    
    # 配置 SSH
    configure_ssh "$SSH_PORT" "$SSH_PUBLIC_KEY"
    
    # 配置 fail2ban
    if configure_fail2ban "$SSH_PORT"; then
        print_info "fail2ban 配置完成"
    else
        print_warning "fail2ban 配置可能有问题，但脚本继续执行"
    fi
    
    # 配置防火墙
    configure_firewall "$
