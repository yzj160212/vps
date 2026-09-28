#!/usr/bin/env bash
#
# deploy-b.sh — 服务器 B 一键部署（开荒 + 反向隧道出口端）
#
#   = 开荒（vps.sh：SSH 加固 / fail2ban / UFW / 日志优化）
#   + 出口端部署（反向隧道 bridge；inbounds 为空，对外不开任何入口）
#
# 架构：用户 --> A(VLESS+REALITY+XHTTP:443) --反向隧道(B主动拨A)--> B --> Internet
#
# 用法：
#   bash deploy-b.sh --token <A 输出的令牌>
#   bash deploy-b.sh --token <令牌> --ssh-port 22222 --ssh-key-file ~/.ssh/id_ed25519.pub
#   bash deploy-b.sh --skip-bootstrap --token <令牌>          # 已经开荒过的机器
#   bash deploy-b.sh --dry-run --token <令牌>                 # 只看生成的配置，不动系统
#   bash deploy-b.sh --help
#
# 配套脚本：deploy-a.sh（在 A 上运行，产出上面那个令牌）
#
# 部署顺序是硬约束：必须先跑完 A 拿到令牌，再跑 B。
#
set -euo pipefail

VERSION="2.0.0"

# ============================ 开荒参数（第 1 步，传给 vps.sh）============================
VPS_SH=""                    # vps.sh 路径；留空则自动查找同目录，找不到就下载
VPS_SH_URL="https://raw.githubusercontent.com/yzj160212/vps/main/vps.sh"
SSH_PORT=""                  # 开荒后 SSH 使用的端口；留空 = 自动随机挑一个高位端口
SSH_KEY=""                   # 开荒要写入 authorized_keys 的 SSH 公钥串
SSH_KEY_FILE=""              # 从文件读取 SSH 公钥（与 SSH_KEY 二选一）
SSH_PORT_MIN=20000           # 自动挑 SSH 端口的下界
SSH_PORT_MAX=60000           # 自动挑 SSH 端口的上界
SKIP_BOOTSTRAP=0             # 1 = 跳过开荒，只部署 Xray
KEEP_SSH_PORT=0              # 1 = 不改动 SSH 端口
BOOTSTRAP_YES=0              # 1 = 开荒阶段不再交互确认
BOOTSTRAP_MARKER="/etc/xray-reverse/bootstrap.done"   # 开荒完成标记（用于识别重跑）

# ============================ 默认参数（第 2 步，出口端）============================
TOKEN=""                     # A 输出的 base64 登记令牌
TOKEN_FILE=""                # 从文件读令牌
A_ADDR=""                    # A 的域名或稳定 IP（不用 --token 时必填）
REVERSE_PORT=""              # A 的反向隧道落点端口（不用 --token 时必填）
REVERSE_DOMAIN=""            # 内部虚拟域名，须与 A 一致
BRIDGE_UUID=""               # A 上 reverse-in 的客户端 UUID（不用 --token 时必填）
VLESS_ENCRYPTION=""          # VLESS Encryption 加密串（不用 --token 时必填）
FORCE=0
SKIP_INSTALL=0
DRY_RUN=0
STATE_DIR="/etc/xray-reverse"

# 允许用 XRAY_BIN 指定 xray 可执行文件（便于 --dry-run 在任意机器上预演）
XRAY_BIN="${XRAY_BIN:-}"

# ============================ 输出工具 ============================
if [[ -t 1 ]]; then
  C_R=$'\033[31m'; C_G=$'\033[32m'; C_Y=$'\033[33m'; C_B=$'\033[36m'; C_D=$'\033[2m'; C_0=$'\033[0m'
else
  C_R=""; C_G=""; C_Y=""; C_B=""; C_D=""; C_0=""
fi
log()  { printf '%s[+]%s %s\n' "$C_G" "$C_0" "$*"; }
info() { printf '%s[·]%s %s\n' "$C_D" "$C_0" "$*"; }
warn() { printf '%s[!]%s %s\n' "$C_Y" "$C_0" "$*" >&2; }
err()  { printf '%s[x]%s %s\n' "$C_R" "$C_0" "$*" >&2; }
die()  { err "$*"; exit 1; }
hr()   { printf '%s\n' "------------------------------------------------------------"; }

# ============================ 用法 ============================
usage() {
  cat <<'EOF'
deploy-b.sh v2.0.0 — 服务器 B 一键部署（开荒 + 反向隧道出口端）

用法：
  bash deploy-b.sh --token <A 输出的令牌>
  bash deploy-b.sh --skip-bootstrap --token <令牌>     # 已经开荒过的机器

第 1 步：开荒选项（调用同目录的 vps.sh）
  --ssh-port <端口>      开荒后 SSH 使用的端口；不填则自动随机挑一个高位端口
  --ssh-key <公钥串>     写入 authorized_keys 的 SSH 公钥；不填则自动从 ~/.ssh/*.pub 里找
  --ssh-key-file <路径>  从文件读取 SSH 公钥
  --keep-ssh-port        不改动 SSH 端口（只做其余加固）
  --skip-bootstrap       跳过开荒，只部署 Xray
  --yes                  开荒阶段不再交互确认（无人值守）
  --vps-sh <路径>        指定本地 vps.sh 路径（默认自动查找，找不到就从仓库下载）

第 2 步：出口端选项
  --token <令牌>          从 deploy-a.sh 输出的登记令牌（推荐，一键打通）
  --token-file <路径>     从文件读取令牌
  --a-addr <域名或IP>     A 的域名或稳定 IP（不用 --token 时必填）
  --reverse-port <端口>   A 的反向隧道落点端口（不用 --token 时必填）
  --bridge-uuid <UUID>    A 上 reverse-in 的客户端 UUID（不用 --token 时必填）
  --encryption <字符串>   VLESS Encryption 加密串（不用 --token 时必填）
  --reverse-domain <域名> 内部虚拟域名，默认 reverse.internal（须与 A 一致）
  --dry-run               只生成并校验配置、打印结果，不改动系统（无需 root，且会跳过开荒）
  --force                 已存在配置时强制覆盖（会先备份）
  --skip-install          不自动安装 Xray
  -h, --help              显示帮助

说明：1) SSH 端口加固已经由第 1 步的开荒脚本负责，所以本脚本不再提供
         「把 SSH 迁到高位端口」的选项 —— 那件事开荒时已经做完了。
      2) B 不需要放行任何入站端口（它只主动外拨到 A），因此没有 --skip-firewall 选项。

环境变量：
  XRAY_BIN                指定 xray 可执行文件路径（--dry-run 时很有用）

示例：
  bash deploy-b.sh --token eyJYQVhfUkVWRVJTRV9FTlJPTExfVjEK...
  bash deploy-b.sh --token <令牌> --ssh-port 22222 --ssh-key-file ~/.ssh/id_ed25519.pub
EOF
}

# ============================ 参数解析 ============================
# 注意：带值的选项统一用「shift; 若还有参数再 shift」的写法。
# 直接写 shift 2 在「选项后面忘了给值」时会因 set -e 抛出一句看不懂的错误。
while [[ $# -gt 0 ]]; do
  case "$1" in
    # ---- 第 1 步：开荒 ----
    --ssh-port)       SSH_PORT="${2:-}";         shift; [[ $# -gt 0 ]] && shift || true ;;
    --ssh-key)        SSH_KEY="${2:-}";          shift; [[ $# -gt 0 ]] && shift || true ;;
    --ssh-key-file)   SSH_KEY_FILE="${2:-}";     shift; [[ $# -gt 0 ]] && shift || true ;;
    --vps-sh)         VPS_SH="${2:-}";           shift; [[ $# -gt 0 ]] && shift || true ;;
    --keep-ssh-port)  KEEP_SSH_PORT=1; shift ;;
    --skip-bootstrap) SKIP_BOOTSTRAP=1; shift ;;
    --yes|-y)         BOOTSTRAP_YES=1; shift ;;
    # ---- 第 2 步：出口端 ----
    --token)          TOKEN="${2:-}";            shift; [[ $# -gt 0 ]] && shift || true ;;
    --token-file)     TOKEN_FILE="${2:-}";       shift; [[ $# -gt 0 ]] && shift || true ;;
    --a-addr|--domain) A_ADDR="${2:-}";          shift; [[ $# -gt 0 ]] && shift || true ;;
    --reverse-port)   REVERSE_PORT="${2:-}";     shift; [[ $# -gt 0 ]] && shift || true ;;
    --reverse-domain) REVERSE_DOMAIN="${2:-}";   shift; [[ $# -gt 0 ]] && shift || true ;;
    --bridge-uuid)    BRIDGE_UUID="${2:-}";      shift; [[ $# -gt 0 ]] && shift || true ;;
    --encryption)     VLESS_ENCRYPTION="${2:-}"; shift; [[ $# -gt 0 ]] && shift || true ;;
    --dry-run)        DRY_RUN=1; shift ;;
    --force)          FORCE=1; shift ;;
    --skip-install)   SKIP_INSTALL=1; shift ;;
    -h|--help)        usage; exit 0 ;;
    *) die "未知参数：$1（用 --help 查看用法）" ;;
  esac
done

# ============================ 前置检查 ============================
if [[ "$DRY_RUN" -eq 0 ]]; then
  [[ ${EUID:-$(id -u)} -eq 0 ]] || die "请以 root 运行（sudo bash $0 ...）"
  command -v systemctl >/dev/null 2>&1 || die "未检测到 systemd，本脚本仅支持 systemd 发行版"
fi
[[ -z "$REVERSE_DOMAIN" ]] && REVERSE_DOMAIN="reverse.internal"
[[ "$REVERSE_DOMAIN" =~ ^[A-Za-z0-9._-]+$ ]] || die "内部域名含非法字符"

if [[ -n "$SSH_PORT" ]]; then
  [[ "$SSH_PORT" =~ ^[0-9]+$ ]] || die "--ssh-port 必须是数字"
  (( SSH_PORT >= 1024 && SSH_PORT <= 65535 )) \
    || die "--ssh-port 需在 1024..65535 之间（开荒脚本不接受特权端口）"
fi
if [[ -n "$SSH_KEY_FILE" && ! -r "$SSH_KEY_FILE" ]]; then
  die "--ssh-key-file 指向的文件不存在或不可读：$SSH_KEY_FILE"
fi
if [[ -n "$SSH_KEY" && -n "$SSH_KEY_FILE" ]]; then
  die "--ssh-key 与 --ssh-key-file 只能给一个"
fi

# ============================ 开荒：辅助函数 ============================

# 在 [min,max] 内取一个随机端口
rand_port_between() {
  local min="$1" max="$2"
  if command -v shuf >/dev/null 2>&1; then
    shuf -i "${min}-${max}" -n 1
  else
    # bash 的 $RANDOM 上限只有 32767，拼两个凑出足够大的范围
    printf '%d' $(( min + ( ((RANDOM << 15) | RANDOM) % (max - min + 1) ) ))
  fi
}

# 找同目录 / 当前目录下的 vps.sh
locate_vps_sh() {
  local d=""
  if [[ -n "${BASH_SOURCE[0]:-}" && -f "${BASH_SOURCE[0]}" ]]; then
    d="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)" || d=""
    if [[ -n "$d" && -r "$d/vps.sh" ]]; then
      VPS_SH="$d/vps.sh"
      return 0
    fi
  fi
  if [[ -r "./vps.sh" ]]; then
    VPS_SH="$(pwd)/vps.sh"
    return 0
  fi
  return 1
}

# 从仓库下载 vps.sh 到临时目录
fetch_vps_sh() {
  local tmp="" out=""
  tmp="$(mktemp -d)"
  out="$tmp/vps.sh"
  info "本地没有 vps.sh，从仓库下载：$VPS_SH_URL"
  if command -v curl >/dev/null 2>&1; then
    curl -fsSL --max-time 60 -o "$out" "$VPS_SH_URL" || true
  fi
  if [[ ! -s "$out" ]] && command -v wget >/dev/null 2>&1; then
    wget -q -O "$out" "$VPS_SH_URL" || true
  fi
  [[ -s "$out" ]] || die "下载 vps.sh 失败，请手动把它放到本脚本同目录后重试。"
  VPS_SH="$out"
  info "vps.sh 已就绪：$VPS_SH"
}

# 自动挑一个 SSH 端口（避开入口端口 / 当前 SSH 端口 / 已占用端口）
pick_ssh_port() {
  local cand="" i ssh_ports=""
  [[ -n "$SSH_PORT" ]] && return 0
  ssh_ports="$(sshd_effective_ports)"
  for (( i=0; i<50; i++ )); do
    cand="$(rand_port_between "$SSH_PORT_MIN" "$SSH_PORT_MAX")"
    if (( cand == 443 || cand == 80 )); then continue; fi
    if [[ -n "$ssh_ports" ]] && printf ' %s ' "$ssh_ports" | grep -qw "$cand"; then continue; fi
    if port_in_use "$cand"; then continue; fi
    SSH_PORT="$cand"
    return 0
  done
  die "连续 50 次都没挑到可用的 SSH 端口，请用 --ssh-port 手动指定一个。"
}

# 自动从 ~/.ssh 里找公钥
detect_ssh_pubkey() {
  local f=""
  for f in "$HOME/.ssh/id_ed25519.pub" "$HOME/.ssh/id_rsa.pub" "$HOME/.ssh/id_ecdsa.pub"; do
    if [[ -r "$f" ]]; then SSH_KEY_FILE="$f"; return 0; fi
  done
  for f in "$HOME"/.ssh/*.pub; do
    [[ -r "$f" ]] || continue
    SSH_KEY_FILE="$f"
    return 0
  done
  return 1
}

# 公钥指纹，用于确认时核对，避免写错公钥把自己锁在门外
pubkey_fingerprint() {
  local src="$1" f=""
  command -v ssh-keygen >/dev/null 2>&1 || { printf '(无 ssh-keygen，无法计算)'; return 0; }
  if [[ -r "$src" && "$src" == */* ]]; then
    ssh-keygen -lf "$src" 2>/dev/null | awk '{print $2}'
  else
    f="$(mktemp)"
    printf '%s\n' "$src" > "$f"
    ssh-keygen -lf "$f" 2>/dev/null | awk '{print $2}'
    rm -f "$f"
  fi
}

# 公钥必须真的能被 ssh-keygen 解析。
# 为什么必须查：开荒在写入公钥的同时会禁用密码登录。如果公钥是「格式看着对
# 但内容坏了」（粘贴截断、Base64 被改坏），它会照常写进 authorized_keys，
# 然后密码登录又被关掉 —— 结果就是彻底锁死在门外。
# 注意这与 vps.sh 的 vps_pubkey_valid() 不重复：那个只查前缀和长度，不查内容。
pubkey_parsable() {
  local src="$1" f="" out=""
  command -v ssh-keygen >/dev/null 2>&1 || return 0   # 没有 ssh-keygen 就不阻塞
  if [[ -r "$src" && "$src" == */* ]]; then
    out="$(ssh-keygen -lf "$src" 2>/dev/null || true)"
  else
    f="$(mktemp)"
    printf '%s\n' "$src" > "$f"
    out="$(ssh-keygen -lf "$f" 2>/dev/null || true)"
    rm -f "$f"
  fi
  [[ -n "$out" ]]
}

# 从终端确认。0=同意，1=不同意或无法询问。
# 优先读 /dev/tty：`curl ... | bash` 时 stdin 是脚本文本本身，绝不能去读它。
ask_confirm() {
  local prompt="$1" ans=""
  if [[ "$BOOTSTRAP_YES" -eq 1 ]]; then return 0; fi
  if [[ -t 0 ]]; then
    printf '%s' "$prompt" >&2
    IFS= read -r ans || ans=""
  elif [[ -r /dev/tty ]]; then
    printf '%s' "$prompt" >&2
    IFS= read -r ans < /dev/tty || ans=""
  else
    return 1
  fi
  [[ "$ans" =~ ^[Yy] ]]
}

# ============================ 开荒：主函数 ============================
run_bootstrap() {
  if [[ "$SKIP_BOOTSTRAP" -eq 1 ]]; then
    log "已跳过开荒（--skip-bootstrap），直接部署 Xray"
    return 0
  fi
  if [[ "$DRY_RUN" -eq 1 ]]; then
    info "dry-run：跳过开荒步骤（不会改动系统）"
    return 0
  fi

  hr
  printf '%s第 1 步 / 共 2 步：开荒%s\n' "$C_B" "$C_0"
  printf '  SSH 加固 / fail2ban / UFW / 日志优化（调用 vps.sh）\n'
  hr

  # 只有在没显式指定 --vps-sh 时才自动查找/下载。
  # 否则 locate_vps_sh 会把用户明确指定的路径覆盖掉。
  if [[ -z "$VPS_SH" ]]; then
    locate_vps_sh || fetch_vps_sh
  fi
  [[ -r "$VPS_SH" ]] || die "--vps-sh 指向的文件不存在或不可读：$VPS_SH"

  # 已经开荒过的机器，默认不重复开荒：重复跑要 apt upgrade，还会 ufw --force reset
  if [[ -f "$BOOTSTRAP_MARKER" && "$FORCE" -ne 1 ]]; then
    warn "检测到本机已经开荒过（存在 $BOOTSTRAP_MARKER）。"
    warn "重复开荒会重新 apt upgrade，并 ufw --force reset 清空防火墙规则"
    warn "（随后本脚本会重新放行 443 与反向端口，但没必要多跑一遍）。"
    if [[ "$BOOTSTRAP_YES" -eq 1 ]]; then
      info "--yes 已指定，继续重新开荒。"
    elif ask_confirm "是否重新开荒？(y/N): "; then
      info "将重新开荒。"
    else
      log "跳过开荒，直接部署 Xray（等价于 --skip-bootstrap）"
      return 0
    fi
  fi

  [[ ${EUID:-$(id -u)} -eq 0 ]] || die "开荒需要 root 权限（sudo bash $0 ...）"

  # --- 决定 SSH 端口 ---
  if [[ "$KEEP_SSH_PORT" -eq 1 ]]; then
    local cur=""
    cur="$(sshd_effective_ports | awk '{print $1}')"
    if [[ -n "$cur" ]] && (( cur >= 1024 && cur <= 65535 )); then
      SSH_PORT="$cur"
      info "已指定 --keep-ssh-port：SSH 端口保持 ${SSH_PORT} 不变"
    else
      warn "当前 SSH 端口是「${cur:-未知}」，开荒脚本不接受 1024 以下（比如 22）的端口。"
      warn "--keep-ssh-port 失效，改为自动随机挑一个。"
      pick_ssh_port
      info "开荒将把 SSH 端口设为：${SSH_PORT}"
    fi
  else
    pick_ssh_port
    info "开荒将把 SSH 端口设为：${SSH_PORT}"
  fi

  # --- 决定 SSH 公钥 ---
  if [[ -z "$SSH_KEY" && -z "$SSH_KEY_FILE" ]]; then
    detect_ssh_pubkey || die "没找到 SSH 公钥。开荒会禁用密码登录，没有可用公钥你会连不上。请用 --ssh-key 或 --ssh-key-file 指定。"
  fi
  local key_src=""
  if [[ -n "$SSH_KEY" ]]; then key_src="$SSH_KEY"; else key_src="$SSH_KEY_FILE"; fi

  # 关键安全检查：公钥内容必须真的可用，否则宁可不做
  if ! pubkey_parsable "$key_src"; then
    die "这个 SSH 公钥无法被 ssh-keygen 解析（可能粘贴不完整或内容被改坏）。
     开荒会同时禁用密码登录，用错公钥会把你彻底锁在门外，因此已中止。
     请检查后用 --ssh-key / --ssh-key-file 重新指定。"
  fi

  # --- 亮明将要做的危险改动，让人确认 ---
  hr
  printf '%s请确认开荒参数（这一步会改动 SSH 登录方式）：%s\n' "$C_Y" "$C_0"
  printf '  SSH 端口  : %s\n' "$SSH_PORT"
  printf '  SSH 公钥  : %s\n' "$key_src"
  printf '  公钥指纹  : %s\n' "$(pubkey_fingerprint "$key_src")"
  printf '  密码登录  : 将被禁用（只允许密钥登录）\n'
  hr
  if [[ "$BOOTSTRAP_YES" -ne 1 ]]; then
    if [[ -t 0 || -r /dev/tty ]]; then
      ask_confirm "确认按以上参数开荒？(y/N): " || die "已取消，未做任何改动。"
    else
      die "无法交互确认。请加 --yes 表示你已确认以上参数（无人值守模式）。"
    fi
  fi

  # --- 调用 vps.sh（非交互）---
  local args=()
  args+=(--yes --no-reboot)
  args+=(--ssh-port "$SSH_PORT")
  if [[ -n "$SSH_KEY" ]]; then
    args+=(--ssh-key "$SSH_KEY")
  elif [[ -n "$SSH_KEY_FILE" ]]; then
    args+=(--ssh-key-file "$SSH_KEY_FILE")
  fi

  log "开始开荒：bash ${VPS_SH} ${args[*]}"
  if ! bash "$VPS_SH" "${args[@]}"; then
    die "开荒失败（vps.sh 返回非零）。系统可能处于中间状态，请检查后用 --skip-bootstrap 重跑本脚本。"
  fi

  # 落标记，下次能识别「已开荒」
  mkdir -p "$STATE_DIR"
  printf 'bootstrapped_at=%s\nssh_port=%s\n' "$(date -Iseconds)" "${SSH_PORT:-unchanged}" > "$BOOTSTRAP_MARKER"
  chmod 600 "$BOOTSTRAP_MARKER"
  log "开荒完成"
  echo
}

need_cmd() { command -v "$1" >/dev/null 2>&1; }

# 注：原 setup-b.sh 里的 SSHD_BIN 解析、sshd_current_ports()、ssh_migrate_stage1()
# 和 ssh_finalize() 已整体删除。SSH 端口加固现在由第 1 步的开荒脚本（vps.sh）负责，
# 留着那套「两阶段迁移」只会在已开荒的机器上制造把 22 重新打开的风险。

# ============================ 安装 Xray ============================
install_xray() {
  if [[ -n "$XRAY_BIN" ]]; then
    [[ -x "$XRAY_BIN" ]] || die "XRAY_BIN 指定的文件不可执行：$XRAY_BIN"
    log "使用指定的 xray：$("$XRAY_BIN" version 2>/dev/null | head -n1)"
    return 0
  fi
  if need_cmd xray; then
    XRAY_BIN="$(command -v xray)"
    log "已检测到 Xray：$("$XRAY_BIN" version 2>/dev/null | head -n1)"
    return 0
  fi
  [[ "$SKIP_INSTALL" -eq 1 ]] && die "未找到 xray，且指定了 --skip-install"
  [[ "$DRY_RUN" -eq 1 ]] && die "未找到 xray。--dry-run 需要可用的 xray，请用 XRAY_BIN 指定路径"

  log "安装 Xray-core ..."
  if ! need_cmd curl && ! need_cmd wget; then
    warn "缺少 curl/wget，尝试用包管理器安装"
    if   need_cmd apt-get; then apt-get update -qq && apt-get install -y -qq curl
    elif need_cmd dnf;     then dnf install -y -q curl
    elif need_cmd yum;     then yum install -y -q curl
    else die "无法安装 curl，请手动安装后重试"; fi
  fi

  if need_cmd curl; then
    bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install
  else
    bash -c "$(wget -qO- https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install
  fi
  need_cmd xray || die "Xray 安装失败"
  XRAY_BIN="$(command -v xray)"
  log "Xray 安装完成：$("$XRAY_BIN" version 2>/dev/null | head -n1)"
}

# ============================ 配置路径 ============================
resolve_conf_dir() {
  if [[ "$DRY_RUN" -eq 1 ]]; then
    XRAY_CONF_DIR="$RUN_DIR/etc"
    STATE_DIR="$RUN_DIR/state"
    mkdir -p "$XRAY_CONF_DIR" "$STATE_DIR"
  elif [[ -d /usr/local/etc/xray ]]; then
    XRAY_CONF_DIR="/usr/local/etc/xray"
  elif [[ -d /etc/xray ]]; then
    XRAY_CONF_DIR="/etc/xray"
  else
    XRAY_CONF_DIR="/usr/local/etc/xray"
    mkdir -p "$XRAY_CONF_DIR"
  fi
  XRAY_CONF="$XRAY_CONF_DIR/config.json"
  info "Xray 配置目录：$XRAY_CONF_DIR"
}

# ============================ 令牌解析 ============================
parse_token() {
  local raw b64 line k v
  if [[ -n "$TOKEN_FILE" ]]; then
    [[ -r "$TOKEN_FILE" ]] || die "无法读取令牌文件：$TOKEN_FILE"
    TOKEN="$(tr -d '[:space:]' < "$TOKEN_FILE")"
  fi
  if [[ -n "$TOKEN" ]]; then
    TOKEN="${TOKEN//$'\n'/}"
    b64="$TOKEN"
    if ! raw="$(printf '%s' "$b64" | base64 -d 2>/dev/null)"; then
      die "令牌不是合法的 base64，请重新从 deploy-a.sh 输出复制"
    fi
    printf '%s\n' "$raw" | grep -q '^XRAY_REVERSE_ENROLL_V1' \
      || die "令牌格式不匹配（缺少版本标识），请重新从 deploy-a.sh 输出复制"

    while IFS= read -r line; do
      [[ "$line" == *=* ]] || continue
      k="${line%%=*}"; v="${line#*=}"
      case "$k" in
        A_ADDR)            A_ADDR="$v" ;;
        REVERSE_PORT)      REVERSE_PORT="$v" ;;
        REVERSE_DOMAIN)    REVERSE_DOMAIN="$v" ;;
        BRIDGE_UUID)       BRIDGE_UUID="$v" ;;
        VLESS_ENCRYPTION)  VLESS_ENCRYPTION="$v" ;;
      esac
    done <<< "$raw"
    log "令牌解析成功"
  fi

  [[ -n "$A_ADDR" ]]           || die "缺少 A 地址：请用 --token 或 --a-addr 指定"
  [[ -n "$REVERSE_PORT" ]]     || die "缺少反向端口：请用 --token 或 --reverse-port 指定"
  [[ -n "$BRIDGE_UUID" ]]      || die "缺少 BRIDGE_UUID：请用 --token 或 --bridge-uuid 指定"
  [[ -n "$VLESS_ENCRYPTION" ]] || die "缺少 VLESS Encryption：请用 --token 或 --encryption 指定"
  [[ "$REVERSE_PORT" =~ ^[0-9]+$ ]] || die "--reverse-port 必须是数字"

  info "A 地址        : ${A_ADDR}"
  info "反向隧道端口  : ${REVERSE_PORT}"
  info "内部域名      : ${REVERSE_DOMAIN}"

  validate_encryption "$VLESS_ENCRYPTION"
}

# 提前校验 VLESS Encryption 串，避免把畸形串喂给 xray
# （Xray 26.x 对畸形串会直接 panic，而不是给出可读报错）
validate_encryption() {
  local e="$1" b3 last
  [[ "$e" =~ ^mlkem768x25519plus\.(native|xorpub|random)\. ]] \
    || die "VLESS Encryption 串格式不对：应以 mlkem768x25519plus.native. / .xorpub. / .random. 开头。
    请回到 A 上执行：xray vlessenc  并原样复制 \`\"encryption\"\` 后面的整串值。"

  b3="$(printf '%s' "$e" | cut -d. -f3)"
  [[ "$b3" =~ ^([0-9]+(-[0-9]+)?s|0rtt)$ ]] \
    || die "VLESS Encryption 串第 3 段应为会话票据时长（如 600s）或 0rtt，实际是「${b3}」。
    请回到 A 上重新复制完整的一整串。"

  last="${e##*.}"
  (( ${#last} >= 43 )) \
    || die "VLESS Encryption 串末尾的认证段疑似被截断或填错（长度 ${#last}，至少 43）。
    请回到 A 上重新复制完整的一整串（很容易漏字符）。"

  info "VLESS Encryption 串格式校验通过"
}

# ============================ 配置写入 ============================
test_xray_config() {
  local f="$1" out=""
  if out="$("$XRAY_BIN" -test -config "$f" 2>&1)"; then return 0; fi
  if out="$("$XRAY_BIN" run -test -config "$f" 2>&1)"; then return 0; fi
  printf '%s\n' "$out" >&2
  return 1
}

# 从 stdin 读取新配置并落盘；失败自动回滚
apply_config() {
  # 注意：临时文件必须以 .json 结尾，否则 xray -test 无法识别配置格式
  local new bak
  new="$(dirname "$XRAY_CONF")/.xray-new-$$.json"
  bak="$XRAY_CONF.bak-$(date +%Y%m%d%H%M%S)"

  cat > "$new"

  if ! test_xray_config "$new"; then
    rm -f "$new"
    die "配置校验未通过，已保留原配置，未做任何改动"
  fi
  log "配置语法校验通过"

  if [[ "$DRY_RUN" -eq 1 ]]; then
    mv "$new" "$XRAY_CONF"
    return 0
  fi

  if [[ -f "$XRAY_CONF" ]]; then
    cp -a "$XRAY_CONF" "$bak"
    info "原配置已备份：$bak"
  fi
  mv "$new" "$XRAY_CONF"

  systemctl daemon-reload >/dev/null 2>&1 || true
  if ! systemctl restart xray; then
    err "xray 重启失败"
    if [[ -f "$bak" ]]; then
      cp -a "$bak" "$XRAY_CONF"
      systemctl restart xray || true
      die "已回滚到备份配置"
    fi
    die "无可用备份，请手动检查"
  fi
  sleep 1
  systemctl is-active --quiet xray || die "xray 未处于 active 状态，请查看：journalctl -u xray -n 50"
  log "xray 已重启并处于 active"
}

# ============================ systemd 自愈 ============================
setup_systemd_selfheal() {
  if [[ "$DRY_RUN" -eq 1 ]]; then
    info "（dry-run）跳过 systemd 自愈配置"
    return 0
  fi
  systemctl enable xray >/dev/null 2>&1 || true
  mkdir -p /etc/systemd/system/xray.service.d
  cat > /etc/systemd/system/xray.service.d/restart.conf <<'EOF'
# 由 deploy-b.sh 写入：B 换 IP / 链路断开后自动重拨
[Service]
Restart=always
RestartSec=5
EOF
  systemctl daemon-reload
  systemctl restart xray
  sleep 1
  systemctl is-active --quiet xray || die "xray 未处于 active 状态"
  log "已启用开机自启 + 故障自愈（Restart=always, RestartSec=5）"
  info "当前策略：$(systemctl show xray -p Restart -p RestartSec --value | tr '\n' ' ')"
}

# ============================ 防火墙 ============================
# B 不需要放行任何入站端口：它是 bridge，只主动外拨到 A 的反向端口。
# 出站方向默认就是放行的，所以这里刻意不做任何防火墙改动。
# （原 setup-b.sh 的 open_port() 只在 SSH 迁移时用过，随迁移一起删掉了。）

# ============================ 主流程 ============================
if [[ "$DRY_RUN" -eq 1 ]]; then
  RUN_DIR="$(mktemp -d)"
  trap 'rm -rf "$RUN_DIR"' EXIT
fi

hr
printf '%s服务器 B（AT&T 出口 / bridge 端）部署%s  v%s' "$C_B" "$C_0" "$VERSION"
[[ "$DRY_RUN" -eq 1 ]] && printf '  %s[dry-run]%s' "$C_Y" "$C_0"
printf '\n'
hr

# 先校验令牌：参数不对就直接退出，不在机器上白装一堆东西
parse_token

# ---- 第 1 步：开荒（--skip-bootstrap 时自动跳过）----
run_bootstrap

# ---- 第 2 步：出口端部署 ----
install_xray
resolve_conf_dir

# 复用检查
if [[ "$DRY_RUN" -eq 0 && -f "$STATE_DIR/state-b.env" && "$FORCE" -ne 1 ]]; then
  warn "检测到已有部署状态：$STATE_DIR/state-b.env"
  warn "如需重新部署，请加 --force"
  die "已中止（未做任何改动）"
fi

# 非空白环境提醒：列出其他服务（脚本不会触碰它们）
if [[ "$DRY_RUN" -eq 0 ]] && command -v ss >/dev/null 2>&1; then
  busy="$(ss -ltnp 2>/dev/null | grep -vE 'xray|sshd' || true)"
  if [[ -n "$busy" ]]; then
    info "当前监听中的其他服务（脚本不会触碰它们）："
    printf '%s\n' "$busy" | sed 's/^/    /'
  fi
fi

log "写入 B 的配置 ..."
apply_config <<EOF
{
  "log": { "loglevel": "warning" },
  "reverse": {
    "bridges": [ { "tag": "bridge", "domain": "${REVERSE_DOMAIN}" } ]
  },
  "inbounds": [],
  "outbounds": [
    {
      "tag": "tunnel",
      "protocol": "vless",
      "settings": {
        "vnext": [ {
          "address": "${A_ADDR}",
          "port": ${REVERSE_PORT},
          "users": [ { "id": "${BRIDGE_UUID}", "encryption": "${VLESS_ENCRYPTION}" } ]
        } ]
      },
      "streamSettings": { "network": "raw" }
    },
    { "tag": "freedom", "protocol": "freedom" }
  ],
  "routing": {
    "rules": [
      { "type": "field", "inboundTag": [ "bridge" ], "domain": [ "full:${REVERSE_DOMAIN}" ], "outboundTag": "tunnel" },
      { "type": "field", "inboundTag": [ "bridge" ], "outboundTag": "freedom" }
    ]
  }
}
EOF

setup_systemd_selfheal

mkdir -p "$STATE_DIR"; chmod 700 "$STATE_DIR"
cat > "$STATE_DIR/state-b.env" <<EOF
# 由 deploy-b.sh 生成于 $(date -Iseconds)
A_ADDR=${A_ADDR}
REVERSE_PORT=${REVERSE_PORT}
REVERSE_DOMAIN=${REVERSE_DOMAIN}
BRIDGE_UUID=${BRIDGE_UUID}
EOF
chmod 600 "$STATE_DIR/state-b.env"

# ============================ 验证 ============================
hr
if [[ "$DRY_RUN" -eq 1 ]]; then
  printf '%s[DRY-RUN] 预演完成，未改动系统%s\n' "$C_G" "$C_0"
  hr
  echo
  printf '%s生成的 B 配置（已通过 xray -test 校验）%s\n' "$C_B" "$C_0"
  cat "$XRAY_CONF"
  echo
  printf '%s正式部署时会在 B 上额外完成：%s\n' "$C_B" "$C_0"
  printf '  · 重启 xray 并校验 active\n'
  printf '  · 写入 /etc/systemd/system/xray.service.d/restart.conf（Restart=always, RestartSec=5）\n'
  printf '  · 校验到 A 的反向隧道是否 ESTAB，并检查对外无多余监听\n'
  hr
  exit 0
fi

printf '%s验证%s\n' "$C_B" "$C_0"
hr
sleep 3

ok=1
printf '  %-46s' "1. xray 服务状态"
if systemctl is-active --quiet xray; then printf '%sactive%s\n' "$C_G" "$C_0"; else printf '%s未运行%s\n' "$C_R" "$C_0"; ok=0; fi

printf '  %-46s' "2. 到 A 的反向隧道连接 (ESTAB)"
estab=""
if command -v ss >/dev/null 2>&1; then
  estab="$(ss -tnpH "dport = :${REVERSE_PORT}" 2>/dev/null | grep -i estab || true)"
fi
if [[ -n "$estab" ]]; then printf '%s已建立%s\n' "$C_G" "$C_0"; else printf '%s未建立（可能仍在重连，稍后重跑本脚本）%s\n' "$C_Y" "$C_0"; fi

printf '  %-46s' "3. 对外监听端口（应只有 SSH）"
if command -v ss >/dev/null 2>&1; then
  listen="$(ss -ltnp 2>/dev/null | grep -vE '127\.0\.0\.1|\[::1\]' || true)"
  if [[ -z "$listen" ]]; then printf '%s无%s\n' "$C_G" "$C_0"; else printf '%s见下%s\n' "$C_Y" "$C_0"; printf '%s\n' "$listen" | sed 's/^/       /'; fi
else
  printf '跳过（无 ss）\n'
fi

printf '  %-46s' "4. inbounds 为空（B 无用户入口）"
if grep -q '"inbounds": \[\]' "$XRAY_CONF"; then printf '%s是%s\n' "$C_G" "$C_0"; else printf '%s否%s\n' "$C_R" "$C_0"; ok=0; fi

echo
if [[ "$ok" -eq 1 ]]; then
  printf '%s服务器 B 部署完成%s\n' "$C_G" "$C_0"
else
  printf '%s部署完成，但有检查项未通过，请看上面标记%s\n' "$C_Y" "$C_0"
fi
hr
printf '出口 IP 自检（应与本机公网 IP 一致）：\n'
curl -fsS --max-time 8 https://api.ipify.org 2>/dev/null | sed 's/^/    /' || printf '    （无法访问外网，请手动检查）\n'
echo
printf '%s换 IP 后无需任何操作%s：隧道由 B 主动外拨到 A 的域名，断线会自动重连。\n' "$C_B" "$C_0"
printf '如需手动验证重连：systemctl restart xray 后 30 秒内重跑本脚本查看第 2 项。\n'
hr
