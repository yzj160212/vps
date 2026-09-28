# Debian 12 VPS 开荒 + Xray 反向隧道 一键部署

每台机器**一条命令**，装完就能用。

---

## 这套东西是干什么的

把「用户入口」和「出口线路」拆开放到两台服务器上：

```
你的设备 ──加密连接──> A 服务器（入口）──反向隧道──> B 服务器（出口）──> 互联网
```

- **A 服务器**：公网稳定、线路好。你的设备连它。
- **B 服务器**：出口线路好（比如 AT&T 家宽）。它主动去连 A，**自己不开放任何端口**，公网扫不到它。

好处：用户流量全部收敛在 A，B 只管出网。**B 换 IP 也不用改任何配置。**

---

## 三个脚本

| 脚本 | 用在哪 | 干什么 |
| --- | --- | --- |
| `vps.sh` | 任意 Debian 12 | 只做开荒：SSH 加固、fail2ban、防火墙、日志优化 |
| `deploy-a.sh` | A 服务器 | 开荒 + 部署入口端 |
| `deploy-b.sh` | B 服务器 | 开荒 + 部署出口端 |

`deploy-a.sh` / `deploy-b.sh` 会自动调用 `vps.sh`，所以**新机器只需要跑一条命令**。

---

## 快速开始

> ⚠️ **顺序不能反：先跑 A、拿到令牌，再跑 B。** B 的令牌是 A 生成的。

### 第 1 步 · A 服务器

```bash
bash <(curl -fsSL vps-yy.vercel.app/a) --domain 你的A的IP或域名
```

`--domain` 填什么：

- **有域名**：填 `a.你的域名.com`（先去域名商加一条 **A 记录**指向 A 的公网 IP）
- **没域名**：直接填 **A 的公网 IP**（最简单，不用配任何东西）

跑完会打印**一行令牌**，形如：

```
【第 2 步】在服务器 B 上执行（复制整行，含长令牌）
  bash deploy-b.sh --token WFJBWV9SRVZFUlNFX0VOUk9MTF9WMQpBX0FERFI9...
```

### 第 2 步 · B 服务器

把上面那行**原样复制**到 B 上执行：

```bash
bash <(curl -fsSL vps-yy.vercel.app/b) --token WFJBWV9SRVZFUlNFX0VOUk9MTF9WMQpBX0FERFI9...
```

### 第 3 步 · 客户端

A 跑完会打印一条 `vless://` 开头的**分享链接**，复制到客户端
（v2rayN / Shadowrocket / Clash 等）导入即可。

---

## ⚠️ 第一次跑之前必读

开荒会**修改 SSH 端口**并**禁用密码登录**（改为只允许密钥）。所以：

1. 提前准备好你的 **SSH 公钥**
   （脚本会自动从 `~/.ssh/*.pub` 找，也可用 `--ssh-key-file` 指定）
2. 跑完后**不要关掉当前 SSH 窗口**，另开一个新终端用新端口登录验证
3. 确认能登录后，再关旧窗口

脚本会在动手前把**新 SSH 端口**和**公钥指纹**打印出来让你确认；公钥写错会直接中止。

---

## 参数说明

### 开荒参数（`deploy-a.sh` 和 `deploy-b.sh` 都有）

| 参数 | 说明 | 默认 |
| --- | --- | --- |
| `--ssh-port <端口>` | 开荒后 SSH 使用的端口 | 随机（20000-60000） |
| `--ssh-key <公钥>` | 写入服务器的 SSH 公钥 | 自动从 `~/.ssh/*.pub` 找 |
| `--ssh-key-file <路径>` | 从文件读取公钥 | 同上 |
| `--skip-bootstrap` | 跳过开荒，只装 Xray（机器已开荒过时用） | 关 |
| `--yes` | 不再交互确认（无人值守） | 关 |

### A 服务器参数

| 参数 | 说明 | 默认 |
| --- | --- | --- |
| `--domain` | **客户端要连的地址**：你的域名或 A 的公网 IP | 自动探测公网 IP |
| `--port` | 用户入口端口 | `443` |
| `--reverse-port` | 反向隧道落点端口 | 随机（20000-60000） |
| `--nodes` | 节点数量（生成 node1..nodeN） | `1` |
| `--sni` | 伪装成访问哪个网站 | `www.apple.com` |
| `--force` | 已部署过时强制重做（会先备份） | 关 |

### B 服务器参数

| 参数 | 说明 |
| --- | --- |
| `--token` | A 输出的令牌（推荐） |
| `--token-file` | 从文件读取令牌 |

### 通用

| 参数 | 说明 |
| --- | --- |
| `--dry-run` | 只生成配置并校验，不改动系统（不需要 root） |
| `--help` | 查看完整帮助 |

---

## 装完怎么确认正常

**在 B 上**：

```bash
systemctl is-active xray     # 应显示 active
RP=$(grep -oE '^REVERSE_PORT=.*' /etc/xray-reverse/state-b.env | cut -d= -f2)
ss -tnp | grep ":$RP"        # 应看到指向 A 的连接（ESTAB）
```

**在 A 上**：

```bash
systemctl is-active xray     # 应显示 active
ufw status                   # 应看到 443 和反向端口已放行
```

**最终确认**：客户端连上后访问 <https://api.ipify.org>，
显示的 IP **应该等于 B 的公网 IP**。如果显示的是 A 的 IP，说明隧道没生效。

---

## 常见问题

**Q：开荒后 SSH 连不上了？**
A：SSH 端口被改了。新端口记在服务器上：

```bash
grep ssh_port /etc/xray-reverse/bootstrap.done
```

如果确实进不去，只能用云厂商的 VNC / 控制台救援。

**Q：忘了 B 的令牌怎么办？**
A：在 A 上重新读出来：

```bash
cat /etc/xray-reverse/enroll-token.txt
```

**Q：`--domain` 填了 `a.example.com` 连不上？**
A：`example.com` 是文档里的示例域名，解析不到你的服务器。
换成你自己的域名，或者直接填 A 的公网 IP。

**Q：`--domain` 的域名需要申请 SSL 证书吗？**
A：不需要。你的域名也不用架任何网站，只要能解析到 A 的 IP 就行。

**Q：机器已经开荒过了，只想重装 Xray 部分？**
A：加 `--skip-bootstrap`。

**Q：部署过一遍了，想重做？**
A：加 `--force`。注意会生成全新密钥，
**已发给客户端的链接全部失效**，需要重新分发。

**Q：只想要开荒，不搭反向隧道？**
A：单独跑开荒脚本：

```bash
bash <(curl -fsSL vps-yy.vercel.app)
```

---

## 卸载

**只卸 Xray**：

```bash
bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ remove
rm -rf /etc/xray-reverse
```

**开荒部分没有自动卸载** —— 它改的是系统安全基线（SSH、防火墙、fail2ban），
自动回退反而更危险。需要的话手动处理，SSH 配置可从 `/etc/ssh/sshd_config.backup.*` 恢复。

---

## 安全提醒

- REALITY 私钥、SSH 私钥等**只留在服务器上**，不要外发、不要截图。
  发给客户端的只有公钥、UUID 和分享链接。
- 只在你自己的机器之间搭建，**不要把 B 做成公开代理入口**。
