#!/usr/bin/env bash
# ============================================================================
# ssh-host-add —— 客户端侧的多服务器 SSH 配置管理器
# ----------------------------------------------------------------------------
# 解决什么问题：
#   SSH 客户端默认会「逐个尝试本地所有私钥」。服务器对每一次尝试都会记一条
#   Failed publickey，而 fail2ban 会把这些全部计为失败 —— 密钥一多，连一次
#   就可能把自己的 IP 封掉。调服务器的 maxretry / MaxAuthTries 治标不治本：
#   20 把密钥就是 20 次失败，100 把就是 100 次，永远追不上。
#
#   正确做法是让客户端「只发那一把对的密钥」，也就是 IdentitiesOnly yes +
#   IdentityFile。本脚本把这件事自动化。
#
# 实测数据（同一台 sshd，都登录成功，但服务器记录的失败次数）：
#   只带正确的密钥   -> 0 次失败
#   把 5 把密钥全带上 -> 4 次失败
#
# 用法：
#   ssh-host-add <别名> <IP或域名> [端口] [用户] [私钥文件]
#
# 例子（下面 IP / 端口 / 私钥名全是占位符，换成你自己的）：
#   ssh-host-add vps-a 203.0.113.10 22022 root ~/.ssh/mykey
#   ssh-host-add vps-b 198.51.100.20 33033 root ~/.ssh/mykey2
#
# 之后连接就用别名即可（不用再写 -i / -p）：
#   ssh vps-a
#
# 约定：
#   1) 私钥统一放在 ~/.ssh/keys/<别名>
#   2) ~/.ssh/config 里加一段
#        Host vps-*
#            User root
#            IdentitiesOnly yes
#            IdentityFile ~/.ssh/keys/%n      ← %n = 你输入的别名
#      这一段是「只发一把密钥」的关键。用 vps-* 做前缀限定，
#      不会影响 github.com 等依赖默认密钥/agent 的其他主机。
# ============================================================================

set -euo pipefail

SSH_DIR="${HOME}/.ssh"
KEY_DIR="${SSH_DIR}/keys"
CONFIG="${SSH_DIR}/config"
PREFIX="${SSH_HOST_PREFIX:-vps-}"

die() { printf '错误: %s\n' "$*" >&2; exit 1; }
info() { printf '%s\n' "$*"; }

usage() {
    cat <<EOF
用法: $(basename "$0") <别名> <IP或域名> [端口] [用户] [私钥文件]

  <别名>      必填。建议以 '${PREFIX}' 开头（脚本会自动为这个前缀配置
              IdentitiesOnly + IdentityFile 令牌）。例：${PREFIX}a
  <IP或域名>  必填。服务器地址
  [端口]      默认 22
  [用户]      默认 root
  [私钥文件]  可选。给了就复制到 ~/.ssh/keys/<别名>；不给则假定你已放好

例子:
  $(basename "$0") ${PREFIX}a 203.0.113.10 22022 root ~/.ssh/mykey

连接:
  ssh ${PREFIX}hk
EOF
}

[ $# -ge 2 ] || { usage; exit 1; }
case "${1:-}" in -h|--help) usage; exit 0 ;; esac

ALIAS="$1"
HOST="$2"
PORT="${3:-22}"
USER_NAME="${4:-root}"
KEY_SRC="${5:-}"

# --- 参数校验 ---------------------------------------------------------------
case "$ALIAS" in
    *[!A-Za-z0-9._-]*) die "别名只能包含字母、数字、点、下划线、连字符：$ALIAS" ;;
esac
case "$PORT" in
    ''|*[!0-9]*) die "端口必须是数字：$PORT" ;;
esac
[ "$PORT" -ge 1 ] && [ "$PORT" -le 65535 ] || die "端口超出范围：$PORT"

# --- 目录与权限 -------------------------------------------------------------
mkdir -p "$SSH_DIR" "$KEY_DIR"
chmod 700 "$SSH_DIR" "$KEY_DIR"
touch "$CONFIG"
chmod 600 "$CONFIG"

# --- 私钥 ---------------------------------------------------------------
if [ -n "$KEY_SRC" ]; then
    [ -f "$KEY_SRC" ] || die "私钥文件不存在：$KEY_SRC"
    if [ -e "${KEY_DIR}/${ALIAS}" ]; then
        info "私钥已存在，跳过复制：${KEY_DIR}/${ALIAS}"
    else
        cp "$KEY_SRC" "${KEY_DIR}/${ALIAS}"
        info "私钥已复制到 ${KEY_DIR}/${ALIAS}"
    fi
    chmod 600 "${KEY_DIR}/${ALIAS}"
else
    if [ -e "${KEY_DIR}/${ALIAS}" ]; then
        info "使用已存在的私钥：${KEY_DIR}/${ALIAS}"
    else
        info "未提供私钥文件，且 ${KEY_DIR}/${ALIAS} 不存在 —— 请自行放好后再连接"
    fi
fi

# --- 前缀段的全局配置（幂等）------------------------------------------------
# 这一段是「只发一把密钥」的关键。用前缀限定作用范围，避免影响
# github.com 之类依赖默认密钥或 ssh-agent 的其他主机。
if grep -qE "^Host[[:space:]]+${PREFIX//./\\.}\*[[:space:]]*$" "$CONFIG" 2>/dev/null; then
    info "前缀配置已存在（Host ${PREFIX}*），跳过"
else
    {
        printf '\n'
        printf '# 由 ssh-host-add 自动生成：只用 ~/.ssh/keys/<别名> 这一把密钥\n'
        printf 'Host %s*\n' "$PREFIX"
        printf '    IdentitiesOnly yes\n'
        printf '    IdentityFile ~/.ssh/keys/%%n\n'
    } >> "$CONFIG"
    info "已写入前缀配置：Host ${PREFIX}*  ->  IdentitiesOnly yes + IdentityFile ~/.ssh/keys/%n"
fi

# --- 单机 Host 段（幂等）----------------------------------------------------
if grep -qE "^Host[[:space:]]+${ALIAS//./\\.}[[:space:]]*$" "$CONFIG" 2>/dev/null; then
    info "别名 ${ALIAS} 已存在于 ${CONFIG}，跳过（如需修改请手动编辑）"
else
    {
        printf '\n'
        printf 'Host %s\n' "$ALIAS"
        printf '    HostName %s\n' "$HOST"
        printf '    Port %s\n' "$PORT"
        printf '    User %s\n' "$USER_NAME"
    } >> "$CONFIG"
    info "已写入主机段：Host ${ALIAS}  ->  ${USER_NAME}@${HOST}:${PORT}"
fi

# --- 校验并提示 -------------------------------------------------------------
if [ "$ALIAS" != "${ALIAS#"$PREFIX"}" ]; then
    :
else
    info ""
    info "提醒：别名不以 '${PREFIX}' 开头，不会命中上面的前缀段，"
    info "      也就拿不到 IdentitiesOnly —— 建议改名，或自行在该别名下加："
    info "          IdentitiesOnly yes"
    info "          IdentityFile ~/.ssh/keys/%n"
fi

info ""
info "现在可以这样连接（不用再写 -i / -p）："
info "    ssh ${ALIAS}"
info ""
info "自查一下客户端到底会发哪把密钥："
info "    ssh -v ${ALIAS} true 2>&1 | grep 'identity file'"
