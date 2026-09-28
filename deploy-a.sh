#!/usr/bin/env bash
#
# deploy-a.sh — 中转机（A）一键部署（开荒 + 反向隧道入口端）
#
#   = 开荒（vps.sh：SSH 加固 / fail2ban / UFW / 日志优化）
#   + 入口端部署（VLESS+REALITY+XHTTP:443 用户入口 + 反向隧道 portal）
#
# 架构：用户 --> A(VLESS+REALITY+XHTTP:443) --反向隧道(B主动拨A)--> B --> Internet
#
# 用法：
#   bash deploy-a.sh --domain a.example.com
#   bash deploy-a.sh --domain a.example.com --ssh-port 22222 --ssh-key-file ~/.ssh/id_ed25519.pub
#   bash deploy-a.sh --skip-bootstrap --domain a.example.com     # 已经开荒过的机器
#   bash deploy-a.sh --dry-run --domain a.example.com            # 只看生成的配置，不动系统
#   bash deploy-a.sh --help
#
# 配套脚本：deploy-b.sh（在落地机 B 上运行，需要本脚本输出的登记令牌）
#
# 部署顺序是硬约束：A 跑完拿到令牌 -> B 才能跑。反过来无解。
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
DEPLOY_B_URL="https://vps-yy.vercel.app/b"      # 交付给落地机的一键命令地址
                                             # （换域名/换仓库时改这里，输出的命令会跟着变）

# ============================ 默认参数（第 2 步，入口端）============================
ENTRY_PORT=443                    # 用户入口端口
REVERSE_PORT=""                   # 落地机（B）反向隧道落点端口；留空 = 部署时随机挑一个高位端口
REVERSE_PORT_MIN=20000            # 随机反向端口的取值下界
REVERSE_PORT_MAX=60000            # 随机反向端口的取值上界
REVERSE_DOMAIN="reverse.internal" # 中转机/落地机内部约定的虚拟域名，两边必须一致
NODES=1                           # 节点数量（node1..nodeN）
REALITY_SNI="www.apple.com"       # REALITY 回落域名（实测可用，见下方 SNI 检查）
XHTTP_PATH=""                     # 留空则自动生成
A_ADDR=""                         # 中转机（A）的域名或公网 IP（生成分享链接用）
STATE_DIR="/etc/xray-reverse"
FORCE=0
SKIP_FIREWALL=0
SKIP_INSTALL=0
DRY_RUN=0
PQ=0                              # 1=使用 ML-KEM-768（后量子）VLESS Encryption
SKIP_SNI_CHECK=0                  # 1=跳过 --sni 回落域名兼容性检查

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
deploy-a.sh v2.0.0 — 中转机（A）一键部署（开荒 + 反向隧道入口端）

用法：
  bash deploy-a.sh --domain a.example.com
  bash deploy-a.sh --skip-bootstrap --domain a.example.com     # 已经开荒过的机器

第 1 步：开荒选项（调用同目录的 vps.sh）
  --ssh-port <端口>      开荒后 SSH 使用的端口；不填则自动随机挑一个高位端口
  --ssh-key <公钥串>     写入 authorized_keys 的 SSH 公钥；不填则自动从 ~/.ssh/*.pub 里找
  --ssh-key-file <路径>  从文件读取 SSH 公钥
  --keep-ssh-port        不改动 SSH 端口（只做其余加固）
  --skip-bootstrap       跳过开荒，只部署 Xray
  --yes                  开荒阶段不再交互确认（无人值守）
  --vps-sh <路径>        指定本地 vps.sh 路径（默认自动查找，找不到就从仓库下载）

第 2 步：入口端选项
  --domain <域名或IP>    中转机（A）的公网地址 —— 客户端就是连这个。两种填法：
                           填域名：如 a.你的域名.com（需先加一条 A 记录指向中转机的 IP）
                           填 IP  ：如 203.0.113.10（最省事，不用配 DNS）
                         不填会自动探测中转机的公网 IP（可用，但域名更抗封锁）。
                         不需要证书、不需要是个真网站。
                         ⚠️ 别和 --sni 搞混：--sni 才是「伪装成哪个网站」。
  --port <端口>          用户入口端口，默认 443（建议保持 443，见 README）
  --reverse-port <端口>  落地机（B）反向隧道落点端口。不填则自动在 20000-60000 里随机挑一个
  --nodes <数量>         节点数量，默认 1（生成 node1..nodeN，各自独立 UUID）
  --sni <域名>           REALITY 伪装的「回落域名」，默认 www.apple.com。
                         必须是支持 TLS 1.3 + X25519 的真实大站。
                         ⚠️ 不要照抄教程里的域名！实测 www.microsoft.com 会让
                         REALITY 握手失败（而表面上一切正常，客户端只报连不上）。
                         部署完会自动做一次 REALITY 自检，失败会提示换域名。
                         和 --domain 完全无关（--domain 是「客户端连哪」）。
  --path <路径>          XHTTP path，默认自动生成随机路径
  --pq                   使用 ML-KEM-768 后量子 VLESS Encryption（默认 X25519）
  --skip-sni-check       跳过部署后的 REALITY 自检（不推荐）
  --dry-run              只生成并校验配置、打印令牌，不改动系统（无需 root，且会跳过开荒）
  --force                已存在配置时强制覆盖（会先备份）
  --skip-firewall        不改动防火墙
  --skip-install         不自动安装 Xray（假设已安装）
  -h, --help             显示帮助

环境变量：
  XRAY_BIN               指定 xray 可执行文件路径（--dry-run 时很有用）

示例：
  bash deploy-a.sh --domain a.example.com
  bash deploy-a.sh --domain a.example.com --nodes 3 --sni www.apple.com --force
  bash deploy-a.sh --domain a.example.com --ssh-port 22222 --ssh-key-file ~/.ssh/id_ed25519.pub
EOF
}

# ============================ 参数解析 ============================
# 注意：带值的选项统一用「shift; 若还有参数再 shift」的写法。
# 直接写 shift 2 在「选项后面忘了给值」时会因 set -e 抛出一句看不懂的错误。
while [[ $# -gt 0 ]]; do
  case "$1" in
    # ---- 第 1 步：开荒 ----
    --ssh-port)       SSH_PORT="${2:-}";        shift; [[ $# -gt 0 ]] && shift || true ;;
    --ssh-key)        SSH_KEY="${2:-}";         shift; [[ $# -gt 0 ]] && shift || true ;;
    --ssh-key-file)   SSH_KEY_FILE="${2:-}";    shift; [[ $# -gt 0 ]] && shift || true ;;
    --vps-sh)         VPS_SH="${2:-}";          shift; [[ $# -gt 0 ]] && shift || true ;;
    --keep-ssh-port)  KEEP_SSH_PORT=1; shift ;;
    --skip-bootstrap) SKIP_BOOTSTRAP=1; shift ;;
    --yes|-y)         BOOTSTRAP_YES=1; shift ;;
    # ---- 第 2 步：入口端 ----
    --domain)         A_ADDR="${2:-}";          shift; [[ $# -gt 0 ]] && shift || true ;;
    --port)           ENTRY_PORT="${2:-}";      shift; [[ $# -gt 0 ]] && shift || true ;;
    --reverse-port)   REVERSE_PORT="${2:-}";    shift; [[ $# -gt 0 ]] && shift || true ;;
    --nodes)          NODES="${2:-}";           shift; [[ $# -gt 0 ]] && shift || true ;;
    --sni)            REALITY_SNI="${2:-}";     shift; [[ $# -gt 0 ]] && shift || true ;;
    --skip-sni-check) SKIP_SNI_CHECK=1; shift ;;
    --path)           XHTTP_PATH="${2:-}";      shift; [[ $# -gt 0 ]] && shift || true ;;
    --pq)             PQ=1; shift ;;
    --dry-run)        DRY_RUN=1; shift ;;
    --force)          FORCE=1; shift ;;
    --skip-firewall)  SKIP_FIREWALL=1; shift ;;
    --skip-install)   SKIP_INSTALL=1; shift ;;
    -h|--help)        usage; exit 0 ;;
    *) die "未知参数：$1（用 --help 查看用法）" ;;
  esac
done

# ============================ 前置检查 ============================
[[ "$ENTRY_PORT" =~ ^[0-9]+$ ]] || die "--port 必须是数字"
[[ "$NODES" =~ ^[0-9]+$ ]] || die "--nodes 必须是数字"
(( NODES >= 1 && NODES <= 64 )) || die "--nodes 需在 1..64 之间"
(( ENTRY_PORT >= 1 && ENTRY_PORT <= 65535 )) || die "--port 超出范围"
if [[ -n "$REVERSE_PORT" ]]; then
  [[ "$REVERSE_PORT" =~ ^[0-9]+$ ]] || die "--reverse-port 必须是数字"
  (( REVERSE_PORT >= 1024 && REVERSE_PORT <= 65535 )) \
    || die "--reverse-port 需在 1024..65535 之间（反向端口没必要用特权端口）"
  [[ "$ENTRY_PORT" != "$REVERSE_PORT" ]] || die "入口端口与反向端口不能相同"
fi
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
[[ "$REVERSE_DOMAIN" =~ ^[A-Za-z0-9._-]+$ ]] || die "内部域名含非法字符"
[[ -n "$REALITY_SNI" ]] || die "--sni 不能为空"

if [[ "$DRY_RUN" -eq 0 ]]; then
  [[ ${EUID:-$(id -u)} -eq 0 ]] || die "请以 root 运行（sudo bash $0 ...）"
  command -v systemctl >/dev/null 2>&1 || die "未检测到 systemd，本脚本仅支持 systemd 发行版"
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
    if (( cand == ENTRY_PORT )); then continue; fi
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

# ============================ 能力校验 ============================
check_capabilities() {
  local help
  help="$("$XRAY_BIN" help 2>&1 || true)"
  grep -q "vlessenc" <<<"$help" \
    || die "当前 Xray 不支持 'vlessenc'（版本过旧）。请升级：bash -c \"\$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)\" @ install"
  grep -q "x25519" <<<"$help" || die "当前 Xray 不支持 'x25519'，请升级 Xray-core"
  info "Xray 能力校验通过（x25519 / uuid / vlessenc 均可用）"
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

# ============================ 密钥生成 ============================
strip_val() { sed -E 's/^[^:]*:[[:space:]]*//; s/^"//; s/",?[[:space:]]*$//' ; }

gen_reality_keypair() {
  local out
  out="$("$XRAY_BIN" x25519)" || die "xray x25519 执行失败"
  REALITY_PRIVATE="$(printf '%s\n' "$out" | grep -iE '^[[:space:]]*PrivateKey' | head -n1 | strip_val)"
  REALITY_PUBLIC="$(printf '%s\n' "$out" | grep -iE 'Password|PublicKey'      | head -n1 | strip_val)"
  [[ -n "$REALITY_PRIVATE" && -n "$REALITY_PUBLIC" ]] \
    || { err "无法解析 xray x25519 输出："; printf '%s\n' "$out" >&2; die "请手动生成 REALITY 密钥"; }
  info "REALITY 密钥对已生成（私钥只写入中转机的配置，绝不外发）"
}

gen_vlessenc() {
  local out idx
  out="$("$XRAY_BIN" vlessenc)" || die "xray vlessenc 执行失败"
  # 第 1 组 = X25519，第 2 组 = ML-KEM-768（后量子）
  idx=$(( PQ ? 2 : 1 ))
  VLESS_DECRYPTION="$(printf '%s\n' "$out" | grep -iE '^[[:space:]]*"?decryption"?[[:space:]]*:' | sed -n "${idx}p" | strip_val)"
  VLESS_ENCRYPTION="$(printf '%s\n' "$out" | grep -iE '^[[:space:]]*"?encryption"?[[:space:]]*:' | sed -n "${idx}p" | strip_val)"
  [[ -n "$VLESS_DECRYPTION" && -n "$VLESS_ENCRYPTION" ]] \
    || { err "无法解析 xray vlessenc 输出："; printf '%s\n' "$out" >&2; die "请手动生成 VLESS Encryption 材料"; }
  if [[ "$PQ" -eq 1 ]]; then
    info "中转机<->落地机 链路加密：ML-KEM-768（后量子）"
  else
    info "中转机<->落地机 链路加密：X25519"
  fi
}

rand_hex() { openssl rand -hex "${1:-8}"; }

# ============================ sshd 生效端口 ============================
# 读取 sshd 当前「生效」的端口列表（空格分隔）。
# 必须容错：本脚本开着 pipefail，如果 sshd 不在 PATH 里，
# 管道里第一个命令返回 127 会让整个管道失败，进而被 set -e 直接中断脚本。
sshd_effective_ports() {
  local bin="" p=""
  if command -v sshd >/dev/null 2>&1; then
    bin="$(command -v sshd)"
  elif [[ -x /usr/sbin/sshd ]]; then
    bin="/usr/sbin/sshd"
  else
    return 0
  fi
  p="$( { "$bin" -T 2>/dev/null || true; } | awk 'tolower($1)=="port"{print $2}' | sort -un )" || true
  printf '%s' "$p" | tr '\n' ' ' | sed 's/ *$//'
}

# ============================ 反向端口选取 ============================
# 生成一个 [REVERSE_PORT_MIN, REVERSE_PORT_MAX] 区间内的随机端口
rand_port() {
  if command -v shuf >/dev/null 2>&1; then
    shuf -i "${REVERSE_PORT_MIN}-${REVERSE_PORT_MAX}" -n 1
  else
    # bash 的 $RANDOM 上限只有 32767，拼两个凑出足够大的范围
    printf '%d' $(( REVERSE_PORT_MIN + ( ((RANDOM << 15) | RANDOM) % (REVERSE_PORT_MAX - REVERSE_PORT_MIN + 1) ) ))
  fi
}

# ============================ 监听套接字（统一封装）============================
# ⚠️ 这里踩过一个大坑，改代码前务必看完：
#
#   `ss` 和 `netstat` 在「没有任何匹配」时**同样会打印表头**。
#   所以任何地方都**不能**用「输出是否为空」来判断端口占用 ——
#   表头会让输出永远非空，于是「端口空闲」被误判成「端口被占用」，
#   脚本在任何机器上都会直接失败。
#
# 另外不使用 ss 的 -H（no-header）开关：那是较新的 iproute2 才有的，
# 老版本会直接报错退出，方向更危险（报错→无输出→误判成空闲）。
# 统一在这里过滤表头，别的地方一律调这个函数。
#
# 过滤方式：只保留真正的数据行。
#   ss -ltnp      → 数据行 $1 == "LISTEN"
#   netstat -tlnp → 数据行 $1 以 tcp 开头、$6 == "LISTEN"
listen_lines() {
  if command -v ss >/dev/null 2>&1; then
    ss -ltnp 2>/dev/null | awk '$1=="LISTEN"' || true
  elif command -v netstat >/dev/null 2>&1; then
    netstat -tlnp 2>/dev/null | awk '$1 ~ /^tcp/ && $6=="LISTEN"' || true
  fi
}

# 端口是否已被监听（挑反向端口时用来避开冲突）
port_in_use() {
  local port="$1"
  [[ -n "$(listen_lines | awk -v p="$port" '$4 ~ "[.:]"p"$"{print; exit}')" ]]
}

# 未显式指定 --reverse-port 时，随机挑一个「没被占用、也不是 SSH/入口端口」的反向端口。
# 用随机高位端口而不是 12345 这种，是为了降低反向监听口被扫到的概率。
pick_reverse_port() {
  local cand="" i ssh_ports=""

  if [[ -n "$REVERSE_PORT" ]]; then
    log "反向隧道端口：${REVERSE_PORT}（由 --reverse-port 指定）"
    return 0
  fi

  ssh_ports="$(sshd_effective_ports)"

  for (( i=0; i<50; i++ )); do
    cand="$(rand_port)"
    if (( cand == ENTRY_PORT )); then continue; fi
    if [[ -n "$ssh_ports" ]] && printf ' %s ' "$ssh_ports" | grep -qw "$cand"; then continue; fi
    if port_in_use "$cand"; then continue; fi
    REVERSE_PORT="$cand"
    log "反向隧道端口：${REVERSE_PORT}（自动随机生成，避开 ${REVERSE_PORT_MIN}-${REVERSE_PORT_MAX} 里的常见端口）"
    return 0
  done

  die "连续 50 次都没挑到可用的反向端口，请用 --reverse-port 手动指定一个。"
}

# ============================ 公网 IP 探测 ============================
detect_public_ip() {
  local ip=""
  for u in https://api.ipify.org https://ifconfig.me/ip https://icanhazip.com; do
    ip="$(curl -fsS --max-time 6 "$u" 2>/dev/null | tr -d '[:space:]')" || true
    if [[ "$ip" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ || "$ip" == *:* ]]; then
      printf '%s' "$ip"; return 0
    fi
  done
  return 1
}

# ============================ --domain 可达性检查 ============================
# --domain 会原样写进分享链接的 @host:port，是客户端唯一要连的地址。
# 填错（打错字 / DNS 没配 / 挂在 Cloudflare 代理后面）客户端就连不上，
# 而那时候你只看到「连不上」，很难想到是这里的问题。
# 所以提前查一次 —— 只警告，不中断，避免误伤合法但少见的部署方式。
check_a_addr_reachable() {
  local addr="$1" resolved="" myip=""

  # 纯 IP：跟本机公网 IP 比一下，不一致通常是 NAT / 弹性 IP
  if [[ "$addr" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ || "$addr" == *:* ]]; then
    myip="$(detect_public_ip || true)"
    if [[ -n "$myip" && "$myip" != "$addr" ]]; then
      warn "你指定的 --domain ${addr} 和本机探测到的公网 IP ${myip} 不一致。"
      warn "如果 A 不是走 NAT/弹性 IP，客户端会连不上 —— 请确认一下。"
    fi
    return 0
  fi

  # 域名：看能不能解析
  if command -v getent >/dev/null 2>&1; then
    resolved="$(getent ahostsv4 "$addr" 2>/dev/null | awk '{print $1}' | sort -u | tr '\n' ' ' | sed 's/ *$//' || true)"
  elif command -v dig >/dev/null 2>&1; then
    resolved="$(dig +short A "$addr" 2>/dev/null | grep -E '^[0-9]' | tr '\n' ' ' | sed 's/ *$//' || true)"
  elif command -v host >/dev/null 2>&1; then
    resolved="$(host -t A "$addr" 2>/dev/null | awk '/has address/{print $4}' | tr '\n' ' ' | sed 's/ *$//' || true)"
  else
    info "系统里没有 getent/dig/host，跳过 --domain 解析检查"
    return 0
  fi

  if [[ -z "$resolved" ]]; then
    warn "无法解析 --domain ${addr} —— 这个域名现在指向不到任何地址，客户端会连不上。"
    warn "请先加一条 A 记录指向中转机的公网 IP，例如："
    warn "    ${addr}  A  <A的公网IP>"
    warn "想跳过域名直接跑，也可以改用公网 IP：--domain <A的公网IP>"
    return 0
  fi

  info "--domain ${addr} 解析到：${resolved}"

  myip="$(detect_public_ip || true)"
  if [[ -n "$myip" ]] && ! printf ' %s ' "$resolved" | grep -qw "$myip"; then
    warn "--domain ${addr} 解析到 ${resolved}，但本机公网 IP 是 ${myip}，两者不一致。"
    warn "常见原因："
    warn "  1. DNS 还没生效 / A 记录写错了 IP"
    warn "  2. 域名挂在 Cloudflare 代理后面（橙云）—— REALITY 必须直连，请改成「仅 DNS」（灰云）"
    warn "确认无误可以忽略本警告。"
  fi
  return 0
}

# ============================ REALITY 端到端自检 ============================
# 为什么必须真测：
#   REALITY 是「把客户端的 uTLS ClientHello 转发给回落域名，拿回 ServerHello」。
#   所以某个域名能不能用，取决于它是否接受**该客户端指纹的 ClientHello** ——
#   openssl 自己的握手能成功，完全不代表 REALITY 能成功。
#   实测：www.microsoft.com（Akamai 承载）openssl 握手正常，但 REALITY 必失败：
#       REALITY: processed invalid connection ... handshake did not complete successfully
#   而客户端只看到 EOF / 连不上，配置、密钥、端口全都「正常」，极难排查。
#
# 做法：用刚生成的密钥起**两个独立实例**（服务端 + 客户端，端口都在高位、只监听
# 127.0.0.1），走一遍真实的 REALITY 握手 + 出网。全程不碰运行中的 xray 服务。
selftest_reality() {
  [[ "$DRY_RUN" -eq 1 ]] && return 0
  [[ "$SKIP_SNI_CHECK" -eq 1 ]] && { info "已跳过 REALITY 自检（--skip-sni-check）"; return 0; }
  command -v timeout >/dev/null 2>&1 || { info "系统无 timeout，跳过 REALITY 自检"; return 0; }

  local dir srv cli sport sportc rc=0
  dir="$(mktemp -d)"
  srv="$dir/srv.json"; cli="$dir/cli.json"
  sport=18443; sportc=18444

  cat > "$srv" <<EOF
{
  "log": { "loglevel": "warning" },
  "inbounds": [ { "tag":"t","listen":"127.0.0.1","port":${sport},"protocol":"vless",
    "settings":{"clients":[{"id":"${NODE_UUIDS[0]}","email":"selftest"}],"decryption":"none"},
    "streamSettings":{"network":"raw","security":"reality",
      "realitySettings":{"target":"${REALITY_SNI}:443","serverNames":["${REALITY_SNI}"],
        "privateKey":"${REALITY_PRIVATE}","shortIds":["${SHORT_ID}"]}} } ],
  "outbounds": [ { "tag":"f","protocol":"freedom" } ]
}
EOF

  cat > "$cli" <<EOF
{
  "log": { "loglevel": "warning" },
  "inbounds": [ { "tag":"s","listen":"127.0.0.1","port":${sportc},"protocol":"socks","settings":{"udp":false} } ],
  "outbounds": [ { "tag":"p","protocol":"vless",
    "settings":{"vnext":[{"address":"127.0.0.1","port":${sport},
      "users":[{"id":"${NODE_UUIDS[0]}","encryption":"none","level":0}]}]},
    "streamSettings":{"network":"raw","security":"reality",
      "realitySettings":{"serverName":"${REALITY_SNI}","fingerprint":"chrome",
        "publicKey":"${REALITY_PUBLIC}","shortId":"${SHORT_ID}"}} } ]
}
EOF

  if ! test_xray_config "$srv" || ! test_xray_config "$cli"; then
    rm -rf "$dir"; warn "自检配置未通过校验，跳过自检"; return 0
  fi

  "$XRAY_BIN" run -config "$srv" > "$dir/srv.log" 2>&1 &
  local ps=$!
  sleep 2
  "$XRAY_BIN" run -config "$cli" > "$dir/cli.log" 2>&1 &
  local pc=$!
  sleep 2

  if timeout 20 curl -s -o /dev/null --max-time 15 -x "socks5h://127.0.0.1:${sportc}" https://api.ipify.org 2>/dev/null; then
    rc=0
  else
    rc=1
  fi
  kill $ps $pc 2>/dev/null; wait $ps $pc 2>/dev/null

  if [[ "$rc" -eq 0 ]]; then
    log "REALITY 自检通过（回落域名 ${REALITY_SNI} 可用）"
  else
    warn "════════════════════════════════════════════════════════"
    warn "REALITY 自检失败！回落域名「${REALITY_SNI}」无法完成 REALITY 握手。"
    warn "服务端报错：$(grep -m1 'REALITY' "$dir/srv.log" 2>/dev/null || echo '（无）')"
    warn ""
    warn "这条链路现在是坏的，但表面上一切「正常」—— 客户端只会连不上。"
    warn "请换一个回落域名重跑，实测可用："
    warn "    --sni www.apple.com     （当前默认值）"
    warn "    --sni www.cloudflare.com"
    warn "    --sni www.bing.com"
    warn "════════════════════════════════════════════════════════"
  fi
  rm -rf "$dir"
  return 0
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

  # 配置已生效，做一次真实的 REALITY 自检
  selftest_reality
}

# ============================ 防火墙 ============================
open_port() {
  local port="$1"
  if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q "Status: active"; then
    ufw allow "${port}/tcp" >/dev/null 2>&1 && log "ufw 已放行 ${port}/tcp" || warn "ufw 放行 ${port}/tcp 失败"
  elif command -v firewall-cmd >/dev/null 2>&1 && systemctl is-active --quiet firewalld 2>/dev/null; then
    firewall-cmd --permanent --add-port="${port}/tcp" >/dev/null 2>&1 \
      && firewall-cmd --reload >/dev/null 2>&1 \
      && log "firewalld 已放行 ${port}/tcp" || warn "firewalld 放行 ${port}/tcp 失败"
  else
    warn "未检测到活动中的 ufw/firewalld —— 请自行确认 ${port}/tcp 已放行（含云厂商安全组）"
  fi
}

# ============================ 端口占用检查 ============================
# ss 的 "sport = :" 过滤器在老版本 iproute2 上可能不支持，故带一层回退
check_port_free() {
  local port="$1" who="" ssh_ports=""
  # 必须走 listen_lines()：直接拿 ss 输出判断，表头会让端口永远"被占用"
  who="$(listen_lines | awk -v p="$port" '$4 ~ "[.:]"p"$"{print}')" || true

  [[ -z "$who" ]] && return 0

  warn "端口 ${port} 已被占用："
  printf '%s\n' "$who" | sed 's/^/    /' >&2

  # 顺手识别是不是撞上了 SSH 端口 —— 这是最常见的误配
  ssh_ports="$(sshd_effective_ports)"
  if [[ -n "$ssh_ports" ]] && printf ' %s ' "$ssh_ports" | grep -qw "$port"; then
    warn "这个端口正是你的 SSH 端口（sshd 生效端口：${ssh_ports}）。"
    warn "SSH 端口不能拿来给 Xray 用，否则两者会抢同一个端口、必有一个起不来。"
    warn "请给 Xray 换一个端口（--port / --reverse-port）。"
  fi

  if [[ "$FORCE" -ne 1 ]]; then
    die "端口被占用。请先处理占用进程，或换端口（--port/--reverse-port）"
  fi
  warn "--force 已指定，继续（可能导致监听失败）"
}

# ============================ 主流程 ============================
if [[ "$DRY_RUN" -eq 1 ]]; then
  RUN_DIR="$(mktemp -d)"
  trap 'rm -rf "$RUN_DIR"' EXIT
fi

# ---- 第 1 步：开荒（--skip-bootstrap 时自动跳过）----
run_bootstrap

# ---- 第 2 步：入口端部署 ----
hr
printf '%s中转机（A · 入口端）部署%s  v%s' "$C_B" "$C_0" "$VERSION"
[[ "$DRY_RUN" -eq 1 ]] && printf '  %s[dry-run]%s' "$C_Y" "$C_0"
printf '\n'
hr

install_xray
check_capabilities
resolve_conf_dir

# 复用已有密钥，避免重跑时把已发出的客户端配置作废
if [[ "$DRY_RUN" -eq 0 && -f "$STATE_DIR/state.env" && "$FORCE" -ne 1 ]]; then
  warn "检测到已有部署状态：$STATE_DIR/state.env"
  warn "直接重跑会生成新密钥，导致已发出的客户端链接全部失效。"
  warn "如需重新部署，请加 --force"
  die "已中止（未做任何改动）"
fi

[[ "$DRY_RUN" -eq 0 ]] && check_port_free "$ENTRY_PORT"

# 未指定 --reverse-port 时在这里随机定下来；此后 REVERSE_PORT 就是一个确定值
pick_reverse_port
[[ "$DRY_RUN" -eq 0 ]] && check_port_free "$REVERSE_PORT"

log "生成密钥材料 ..."
gen_reality_keypair
gen_vlessenc
BRIDGE_UUID="$("$XRAY_BIN" uuid)"
[[ -n "$BRIDGE_UUID" ]] || die "xray uuid 执行失败"
SHORT_ID="$(rand_hex 8)"
[[ -z "$XHTTP_PATH" ]] && XHTTP_PATH="/$(rand_hex 8)"
[[ "$XHTTP_PATH" == /* ]] || XHTTP_PATH="/$XHTTP_PATH"
XHTTP_PATH_ENC="%2F${XHTTP_PATH#/}"

# 节点列表
NODE_UUIDS=(); NODE_EMAILS=()
for (( i=1; i<=NODES; i++ )); do
  u="$("$XRAY_BIN" uuid)"; [[ -n "$u" ]] || die "xray uuid 执行失败"
  NODE_UUIDS+=("$u"); NODE_EMAILS+=("node${i}")
done

# 公网地址
if [[ -z "$A_ADDR" ]]; then
  A_ADDR="$(detect_public_ip || true)"
  [[ -n "$A_ADDR" ]] || die "无法自动探测公网 IP，请用 --domain 指定"
  warn "未指定 --domain，自动使用公网 IP：$A_ADDR（建议改用域名）"
else
  # --domain 就是「客户端要连的地址」，会原样写进分享链接的 @host:port。
  # 填错了客户端根本连不上，所以这里做一次只警告不致命的可达性检查。
  check_a_addr_reachable "$A_ADDR"
fi

# 组装 clients / users 片段
CLIENTS_JSON=""
for i in "${!NODE_EMAILS[@]}"; do
  [[ -n "$CLIENTS_JSON" ]] && CLIENTS_JSON+=","
  CLIENTS_JSON+=$'\n            { "id": "'"${NODE_UUIDS[$i]}"'", "email": "'"${NODE_EMAILS[$i]}"'" }'
done
USERS_JSON=""
for e in "${NODE_EMAILS[@]}"; do
  [[ -n "$USERS_JSON" ]] && USERS_JSON+=", "
  USERS_JSON+="\"$e\""
done

log "写入中转机的配置 ..."
# 注意：不要在这里声明 tag=portal 的出站。
# Xray 的 reverse portal 会自行注册同名出站处理器，手写一个 vless 出站
# 既过不了配置校验（"vnext" should have one and only one member），
# 也可能与 portal 冲突。路由里引用 "portal" 即可。
apply_config <<EOF
{
  "log": { "loglevel": "warning" },
  "reverse": {
    "portals": [ { "tag": "portal", "domain": "${REVERSE_DOMAIN}" } ]
  },
  "inbounds": [
    {
      "tag": "user-in",
      "listen": "0.0.0.0",
      "port": ${ENTRY_PORT},
      "protocol": "vless",
      "settings": {
        "clients": [${CLIENTS_JSON}
        ],
        "decryption": "none"
      },
      "streamSettings": {
        "network": "xhttp",
        "security": "reality",
        "xhttpSettings": { "path": "${XHTTP_PATH}", "mode": "auto" },
        "realitySettings": {
          "target": "${REALITY_SNI}:443",
          "serverNames": [ "${REALITY_SNI}" ],
          "privateKey": "${REALITY_PRIVATE}",
          "shortIds": [ "${SHORT_ID}" ]
        }
      }
    },
    {
      "tag": "reverse-in",
      "listen": "0.0.0.0",
      "port": ${REVERSE_PORT},
      "protocol": "vless",
      "settings": {
        "clients": [ { "id": "${BRIDGE_UUID}" } ],
        "decryption": "${VLESS_DECRYPTION}"
      },
      "streamSettings": { "network": "raw" }
    }
  ],
  "outbounds": [
    { "tag": "freedom", "protocol": "freedom" }
  ],
  "routing": {
    "rules": [
      { "type": "field", "inboundTag": [ "reverse-in" ], "domain": [ "full:${REVERSE_DOMAIN}" ], "outboundTag": "portal" },
      { "type": "field", "user": [ ${USERS_JSON} ], "outboundTag": "portal" }
    ]
  }
}
EOF

# 防火墙
if [[ "$DRY_RUN" -eq 0 ]]; then
  if [[ "$SKIP_FIREWALL" -eq 0 ]]; then
    open_port "$ENTRY_PORT"
    open_port "$REVERSE_PORT"
  else
    info "已跳过防火墙配置（--skip-firewall）"
  fi
fi

# 落盘状态
mkdir -p "$STATE_DIR"; chmod 700 "$STATE_DIR"
cat > "$STATE_DIR/state.env" <<EOF
# 由 deploy-a.sh 生成于 $(date -Iseconds)
A_ADDR=${A_ADDR}
ENTRY_PORT=${ENTRY_PORT}
REVERSE_PORT=${REVERSE_PORT}
REVERSE_DOMAIN=${REVERSE_DOMAIN}
REALITY_SNI=${REALITY_SNI}
XHTTP_PATH=${XHTTP_PATH}
REALITY_PUBLIC=${REALITY_PUBLIC}
SHORT_ID=${SHORT_ID}
BRIDGE_UUID=${BRIDGE_UUID}
VLESS_ENCRYPTION=${VLESS_ENCRYPTION}
NODES=${NODES}
EOF
chmod 600 "$STATE_DIR/state.env"
# 私钥单独存，权限收紧
printf 'REALITY_PRIVATE=%s\nVLESS_DECRYPTION=%s\n' "$REALITY_PRIVATE" "$VLESS_DECRYPTION" > "$STATE_DIR/secrets.env"
chmod 600 "$STATE_DIR/secrets.env"

# 交付给落地机（B）的登记令牌
TOKEN_PLAIN="$(cat <<EOF
XRAY_REVERSE_ENROLL_V1
A_ADDR=${A_ADDR}
REVERSE_PORT=${REVERSE_PORT}
REVERSE_DOMAIN=${REVERSE_DOMAIN}
BRIDGE_UUID=${BRIDGE_UUID}
VLESS_ENCRYPTION=${VLESS_ENCRYPTION}
EOF
)"
TOKEN="$(printf '%s' "$TOKEN_PLAIN" | base64 | tr -d '\n')"
printf '%s\n' "$TOKEN" > "$STATE_DIR/enroll-token.txt"
chmod 600 "$STATE_DIR/enroll-token.txt"

# 客户端分享链接
LINKS_FILE="$STATE_DIR/client-links.txt"
: > "$LINKS_FILE"
for i in "${!NODE_EMAILS[@]}"; do
  printf 'vless://%s@%s:%s?encryption=none&security=reality&type=xhttp&path=%s&mode=auto&sni=%s&fp=chrome&pbk=%s&sid=%s#%s\n' \
    "${NODE_UUIDS[$i]}" "$A_ADDR" "$ENTRY_PORT" "$XHTTP_PATH_ENC" "$REALITY_SNI" \
    "$REALITY_PUBLIC" "$SHORT_ID" "${NODE_EMAILS[$i]}" >> "$LINKS_FILE"
done
chmod 600 "$LINKS_FILE"

# 输出
hr
if [[ "$DRY_RUN" -eq 1 ]]; then
  printf '%s[DRY-RUN] 预演完成，未改动系统%s\n' "$C_G" "$C_0"
else
  printf '%s中转机（A）部署完成%s\n' "$C_G" "$C_0"
fi
hr
echo
if [[ "$DRY_RUN" -eq 1 ]]; then
  printf '%s生成的 A 配置（已通过 xray -test 校验）%s\n' "$C_B" "$C_0"
  cat "$XRAY_CONF"
  echo
fi
printf '%s【第 2 步】在落地机（B）上执行下面这一整行%s\n' "$C_B" "$C_0"
printf '%s  从「bash」开始、到行尾为止，整行复制（不要只复制后面的令牌）%s\n' "$C_D" "$C_0"
echo
printf '  bash <(curl -fsSL %s) --token %s\n' "$DEPLOY_B_URL" "$TOKEN"
echo
printf '%s  若落地机上已经有 deploy-b.sh 文件，也可以直接执行：%s\n' "$C_D" "$C_0"
printf '%s      bash deploy-b.sh --token <上面那串令牌>%s\n' "$C_D" "$C_0"
echo
printf '%s【客户端分享链接】%s\n' "$C_B" "$C_0"
cat "$LINKS_FILE"
echo
if [[ "$DRY_RUN" -eq 0 ]]; then
  printf '%s【本地留存材料】%s\n' "$C_B" "$C_0"
  printf '  状态文件（含公钥/短ID，可安全留档）：%s\n' "$STATE_DIR/state.env"
  printf '  私密材料（REALITY 私钥 / VLESS Encryption，绝不外发）：%s\n' "$STATE_DIR/secrets.env"
  printf '  反向隧道令牌：%s\n' "$STATE_DIR/enroll-token.txt"
  echo
  printf '%s【验证清单】%s\n' "$C_B" "$C_0"
  printf '  systemctl is-active xray                       # 应为 active\n'
  printf '  ss -ltnp | grep -E ":%s|:%s"       # 两个端口都在监听\n' "$ENTRY_PORT" "$REVERSE_PORT"
  printf '  journalctl -u xray -n 50 --no-pager            # 看是否有报错\n'
fi
echo
printf '%s注意%s：中转机侧配置与防火墙%s不依赖落地机的 IP%s，落地机换 IP 无需任何改动。\n' "$C_Y" "$C_0" "$C_Y" "$C_0"
hr
