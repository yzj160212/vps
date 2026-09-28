# Debian 12 VPS 开荒 + Xray 反向隧道 一键部署

本仓库三个脚本，都是 Bash（不需要 Python）：

| 脚本 | 用在 | 干什么 | 一条命令 |
| --- | --- | --- | --- |
| `vps.sh` | 任意 Debian 12 机器 | 只做开荒：SSH 加固 / fail2ban / UFW / 日志优化 | `bash <(curl -fsSL vps-yy.vercel.app)` |
| `deploy-a.sh` | 服务器 A（入口 / portal） | **第 1 步** 开荒（调用 `vps.sh`）→ **第 2 步** 装 Xray、生成全部密钥、写配置、开防火墙、输出客户端链接 + B 的登记令牌 | `bash <(curl -fsSL vps-yy.vercel.app/a) --domain a.example.com` |
| `deploy-b.sh` | 服务器 B（AT&T 出口 / bridge） | **第 1 步** 开荒（调用 `vps.sh`）→ **第 2 步** 装 Xray、写 bridge 配置、开自愈、验证隧道 | `bash <(curl -fsSL vps-yy.vercel.app/b) --token <令牌>` |

反向隧道的架构：

```
用户设备 ──VLESS+REALITY+XHTTP:443──> 服务器 A ──反向隧道(B主动拨A)──> 服务器 B ──> Internet
          (境外好线路，用户并发全在 A 收敛)   (AT&T 线路，入站新连接≈0)
```

---

## 只想用开荒脚本（不搭反向隧道）

```bash
bash <(curl -fsSL vps-yy.vercel.app)
```

会交互式问你 SSH 端口和公钥，然后完成 SSH 加固 / fail2ban / UFW / 日志优化。
**不传任何参数时行为与旧版完全一致。**

也可以非交互（供自动化调用）：

```bash
bash <(curl -fsSL vps-yy.vercel.app) --ssh-port 22222 --ssh-key-file ~/.ssh/id_ed25519.pub --yes --no-reboot
```

---

## 一键部署反向隧道

**每台机器一条命令**，开荒和 Xray 部署一次做完。

> **所有脚本都是 Bash，不需要 Python、不需要上传任何东西。**
> 下面两种方式选一种即可。

### 方式一：直接在服务器上拉取执行（推荐，不用上传）

```bash
# A 服务器
bash <(curl -fsSL vps-yy.vercel.app/a) --domain a.example.com

# B 服务器（把 A 跑完打印的令牌贴进去）
bash <(curl -fsSL vps-yy.vercel.app/b) --token <令牌>
```

不用短域名也行，直接用 raw 地址：

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/yzj160212/vps/main/deploy-a.sh) --domain a.example.com
bash <(curl -fsSL https://raw.githubusercontent.com/yzj160212/vps/main/deploy-b.sh) --token <令牌>
```

> **为什么用 `bash <(curl ...)` 而不是 `curl ... | bash`？**
> `curl | bash` 时脚本从 stdin 进来，参数会被 bash 自己吃掉 —— 必须写成 `| bash -s -- --domain x`，
> 少一个字符就报 `bash: --domain: invalid option`。
> `bash <(curl ...)` 把脚本当文件喂给 bash，参数直接跟在后面，不会踩这个坑。

> `deploy-*.sh` 会自动处理 `vps.sh`：先找脚本同目录，找不到就从本仓库下载。
> 所以用上面这种方式跑时**不需要**额外准备 `vps.sh`。

### 方式二：先上传再执行

```bash
# 在你本机（每台机器都需要 vps.sh + 对应的 deploy 脚本）
scp vps.sh deploy-a.sh root@<A的IP>:/root/
scp vps.sh deploy-b.sh root@<B的IP>:/root/

# 然后在服务器上
bash deploy-a.sh --domain a.example.com
```

`vps.sh` 必须和 `deploy-*.sh` 放在**同一个目录**（否则脚本会去仓库下载一份）。

> 也可以只用 `--vps-sh /path/to/vps.sh` 显式指定路径。

### 第 1 步 · 服务器 A

```bash
bash <(curl -fsSL vps-yy.vercel.app/a) --domain a.example.com
```

脚本会先开荒（问你确认 SSH 端口和公钥），再部署 Xray。跑完会打印一条**登记令牌**和一行命令：

```
【第 2 步】在服务器 B 上执行（复制整行，含长令牌）
  bash deploy-b.sh --token WFJBWV9SRVZFUlNFX0VOUk9MTF9WMQpBX0FERFI9...
```

### 第 2 步 · 服务器 B

把上一步那行原样复制到 B 上执行：

```bash
bash <(curl -fsSL vps-yy.vercel.app/b) --token WFJBWV9SRVZFUlNFX0VOUk9MTF9WMQpBX0FERFI9...
```

完成。客户端用 A 输出的 `vless://` 链接导入即可。

> **顺序是硬约束。** B 的令牌是 A 的产出，所以必须 **A 先跑完 → 拿到令牌 → 再跑 B**。
> 不存在「两台同时一键装」的玩法。

### 想先看配置再动手（不改系统、不需要 root）

`--dry-run` 会自动跳过开荒，只生成配置并跑 `xray -test` 校验：

```bash
XRAY_BIN=/usr/local/bin/xray bash deploy-a.sh --dry-run --domain a.example.com
XRAY_BIN=/usr/local/bin/xray bash deploy-b.sh --dry-run --token <令牌>
```

---

## `--domain` 到底填什么？（最容易搞错的一个参数）

**一句话：填 A 服务器的公网地址 —— 客户端就是连它。**

`a.example.com` 只是占位符（`example.com` 是国际标准里专门留给文档示例的域名，**不能真用**）。
你要换成自己的。两种填法：

| 填法 | 例子 | 需要做什么 |
| --- | --- | --- |
| **填域名**（推荐） | `--domain a.你的域名.com` | 去域名商加一条 **A 记录**：`a.你的域名.com` → A 的公网 IP |
| **填 IP**（最省事） | `--domain 203.0.113.10` | 什么都不用配，直接能用 |

不填也可以 —— 脚本会自动探测 A 的公网 IP，但会提示你「建议改用域名」。

### 这个域名不需要证书，也不需要是个真网站

很多人卡在这里。**REALITY 不需要你给域名申请 TLS 证书**，你的域名也不需要架任何网站。
它唯一的作用就是「客户端连接时解析到 A 的 IP」。证书那件事是 REALITY 去伪装成 `--sni` 指定的站，
跟你自己的域名无关。

### ⚠️ 别和 `--sni` 搞混

这两个都是「域名」，但角色完全相反。看生成的分享链接就清楚了：

```
vless://eae648e3-...@a.example.com:443?...&sni=www.apple.com&...
                   ↑ --domain                  ↑ --sni
              客户端要连的地址            客户端伪装成访问哪个站
```

| 参数 | 作用 | 填什么 |
| --- | --- | --- |
| `--domain` | **客户端要连的地址** | 你自己的域名（需 A 记录指向 A 的 IP）或 A 的公网 IP |
| `--sni` | **伪装成访问哪个网站** | 一个真正能握手成功的国外大站，默认 `www.apple.com`。⚠️ 见下文专节，**不要照抄教程** |

`--sni` 跟你的服务器、你的域名**没有任何关系** —— 它只是让流量看起来像在访问苹果官网。

### 脚本会自动帮你检查 `--domain`

填错的话客户端根本连不上，而且报错只会是「连不上」，很难联想到是这里的问题。
所以 `deploy-a.sh` 会做一次**只警告不中断**的检查：

- 域名解析不了 → 提示你先加 A 记录，或改用 IP
- 解析到了，但和 A 本机的公网 IP 不一致 → 提示两种常见原因：
  1. DNS 还没生效 / A 记录 IP 写错了
  2. 域名挂在 **Cloudflare 代理（橙云）** 后面 —— REALITY 必须直连，要改成「仅 DNS」（灰云）

看到警告不等于一定错（NAT、弹性 IP 等情况下也会提示），确认没问题就忽略。

---

## ⚠️ `--sni` 回落域名必须实测可用（踩过大坑）

**这条不是「随便填个大站就行」。填错的话整条链路全废，而且表面上一切正常。**

### 为什么会这样

REALITY 的握手原理是：服务端把**客户端的 uTLS ClientHello 转发给回落域名**，
拿回 ServerHello 后再接管连接。所以这个域名能不能用，取决于
**它是否接受你这个客户端指纹的 ClientHello** —— 不是「能不能 TLS 握手」这么简单。

### 实测结果（同一台机器、同一套密钥，只换域名）

| 回落域名 | 结果 |
| --- | --- |
| `www.microsoft.com` | ❌ **REALITY 握手失败** |
| `www.apple.com` | ✅ 可用（**当前默认值**） |
| `www.cloudflare.com` | ✅ 可用 |
| `www.bing.com` | ✅ 可用 |
| `www.lovelive-anime.jp` | ✅ 可用 |

`www.microsoft.com` 由 Akamai 承载，不接受该指纹的 ClientHello，服务端会报：

```
REALITY: processed invalid connection ... handshake did not complete successfully
```

而客户端只能看到 `failed to POST ... EOF` —— **完全看不出是域名的问题**。
配置语法、密钥对、端口、服务状态、防火墙全都「正常」，极难排查。

### ⚠️ 别用 openssl 去「验证」域名

`openssl s_client -connect www.microsoft.com:443 -tls1_3` 是**成功**的
（返回 `Verify return code: 0`），但 REALITY 依然失败 —— 因为 openssl 发的是
它自己的 ClientHello，跟客户端的 uTLS 指纹不是一回事。
**openssl 能连上 ≠ REALITY 能用。**

### 脚本怎么帮你

`deploy-a.sh` 在部署完成后会自动跑一次 **REALITY 自检**：
用刚生成的密钥在本机起两个临时实例（服务端 + 客户端，只监听 `127.0.0.1` 高位端口），
真跑一遍 REALITY 握手并出网。**全程不碰运行中的 xray 服务。**

- 通过 → `[+] REALITY 自检通过（回落域名 xxx 可用）`
- 失败 → 打印醒目警告 + 服务端报错 + 可用域名列表

想跳过自检用 `--skip-sni-check`（不推荐）。

### 想换回落域名

```bash
bash <(curl -fsSL vps-yy.vercel.app/a) --domain <A的地址> --sni www.cloudflare.com --force
```

选域名的原则：**国外、大站、不跳转、支持 TLS 1.3 + X25519 + H2**。
换完一定看自检结果。

---

## ⚠️ 合并后必须知道的三件事

### 1. 中途失败可能把你锁在门外

开荒会**改 SSH 端口**并**禁用密码登录**。合并成一条命令之后，原来「开荒跑完先验证一下新端口能不能登录」的那个天然检查点没有了。

脚本为此做了三件事，但仍请你自己确认：

- 开荒前会把 **SSH 端口 + 公钥指纹** 打印出来让你确认（`--yes` 可跳过确认）；
- 公钥会先做格式与长度校验，写错就直接中止，**不会**带着坏公钥去禁用密码登录；
- 全流程**默认不重启**（`--no-reboot`），避免重启打断后续步骤。

**第一次在新机器上跑，请务必：**

1. 确认你给的公钥确实是你现在用的那把私钥对应的公钥；
2. 跑完后**不要关掉当前 SSH 会话**，另开一个新终端用新端口登录验证；
3. 验证通过后再关旧会话。

万一真的连不上，只能走云厂商的 VNC / 控制台救援。

### 2. 合并后整个流程要求 Debian 12

`vps.sh` 检测到非 Debian 12 会停下来确认。Xray 部分本身支持任何 systemd 发行版，但开荒部分是专为 Debian 12 写的。非 Debian 12 请加 `--skip-bootstrap`，只用第 2 步。

### 3. 重复跑开荒会重置防火墙

开荒里有一句 `ufw --force reset`，会**清空所有 UFW 规则**。脚本已内置防护：

- 开荒成功后写标记 `/etc/xray-reverse/bootstrap.done`；
- 之后重跑 `deploy-*.sh` 时检测到该标记，会**问你要不要重新开荒，默认跳过**；
- 即使重新开荒了，同一轮里的第 2 步会重新放行 443 和反向端口，所以隧道不会断。

真正有风险的是**单独重跑 `vps.sh`**（不走 deploy 脚本）——那会把 A 的反向端口放行抹掉。补救：

```bash
# 在 A 上执行
ufw allow 443/tcp
RP=$(grep -oE '^REVERSE_PORT=.*' /etc/xray-reverse/state.env | cut -d= -f2)
ufw allow "${RP}/tcp"
ufw status | grep -E "443|${RP}"
```

---

## 端口怎么分配

| 端口 | 用途 | 谁在用 | 谁放行 |
| --- | --- | --- | --- |
| `20000-60000` 里随机一个 | **SSH 登录** | `sshd` | 开荒脚本自动放行 |
| `443` | **用户入口**，客户端连它（VLESS+REALITY+XHTTP） | A 上的 `xray` | 开荒脚本 + 部署脚本放行 |
| `20000-60000` 里随机一个 | **反向隧道落点**，B 主动拨进来 | A 上的 `xray` | 部署脚本自动 `ufw allow` |

**要点：**

- **SSH 端口现在是随机的**：开荒默认在 `20000-60000` 里挑一个，挑完打印出来，也写进 `/etc/xray-reverse/bootstrap.done`。想固定用 `--ssh-port 22222`。
- **不要拿 SSH 端口给 Xray 用。** SSH 端口归 sshd，Xray 用它必然抢端口，必有一个起不来。脚本会在写入配置前检测并拦下来。
- **443 建议保持默认**：REALITY 的伪装效果依赖 443，Xray 对非 443 端口会告警（`Listening on non-443 ports may get your IP blocked by the GFW`）。
- **反向端口默认随机**：`deploy-a.sh` 在 `20000-60000` 里随机挑，避开入口端口、SSH 端口和已被占用的端口。挑好后写进令牌，B 自动同步，**不需要你手动告诉 B**。
  - 想固定：`--reverse-port 23456`（`1024-65535`，且不能等于入口端口）。
- **B 不需要任何入站放行。** 它是 bridge，只主动外拨到 A，所以 `deploy-b.sh` 没有 `--skip-firewall` 这类选项——没东西可放行。

---

## ⚠️ fail2ban：三个会让它「启动正常但完全不封禁」的坑

fail2ban 最坑的地方是**失败是静默的**：服务 active、jail 已加载、日志无报错，
但攻击者怎么爆破都不被封。真机上逐项验证过，三个坑如下。

### 坑 1：filter 模式用了默认的 `normal`（最关键）

本套配置**禁用了密码登录**，攻击者只能试密钥。客户端试密钥时先发"查询"不签名，
sshd 直接拒绝、**不会记录 `Failed publickey`**，只在连接结束时留下：

```
Connection closed by authenticating user root <IP> port N [preauth]
```

而 `normal` 模式把这一行标成 `<F-NOFAIL>`（不计入失败）→ **用真实用户名爆破密钥永远不会被封禁**。

实测（同一份 journal）：

| 模式 | 匹配到的行数 |
| --- | --- |
| `normal`（默认） | **0** ❌ |
| `aggressive` | **8** ✅（日志里总共就 8 条） |

**正确写法：`filter = sshd[mode=aggressive]`**

⚠️ **写成单独一行 `mode = aggressive` 是无效的** —— fail2ban 不会把 jail 级的 `mode`
转发给 filter。虽然 filter 文件自己的注释里写着「在 jail 里写 `mode = extra`」，
但那是错的。真机 A/B 实测（各发 4 次错误密钥）：

| 写法 | 识别到失败次数 |
| --- | --- |
| `filter = sshd` + 单独一行 `mode = aggressive` | **0** ❌ |
| `filter = sshd[mode=aggressive]` | **4** ✅ |
| `filter = sshd[mode=ddos]` | **4** ✅ |

### 坑 2：jail.local 里的 `port` 没被改成真实 SSH 端口

开荒脚本会把 SSH 端口改掉，jail.local 里必须同步，否则封禁规则会打到 **22 端口**上 ——
22 上根本没有服务，等于完全没保护。

早先的实现是 `sed -i "s/port = ssh/port = $ssh_port/"`，**只认单空格**。
配置文件里一旦对齐成 `port    = ssh` 就静默替换失败。现在改成按段定位、容忍任意空白，
并在替换后校验，失败会强制写入 + 报错。

### 坑 3：`allowipv6` 写错了位置

`allowipv6` 是 **fail2ban 主配置**的选项，不是 jail 的选项。
写进 `jail.local` 的全局段只会得到一句 WARNING，而且完全不生效。
正确做法是写进 `/etc/fail2ban/fail2ban.local`：

```ini
[Definition]
allowipv6 = auto
```

（IPv6 封禁本身不需要额外配置 —— `banaction` 会自动同时写 `iptables` 和 `ip6tables`，
实测封禁 IPv6 地址时 ip6tables 规则正常生成。）

### 开荒脚本内置了自检

`vps.sh` 装完 fail2ban 后会跑 `verify_fail2ban()`：

1. 服务是否 active、jail 是否加载
2. **用一个保留地址（`203.0.113.1`）试封一次**，直接看 iptables 规则落在哪个端口
   —— 端口不对就报警（这是「服务正常但不保护」的典型症状）
3. 检查 `filter` 那一行是否写成了 `sshd[mode=aggressive]` 或 `[mode=ddos]`

装完请留意这几行输出，有问题会明确告诉你。

### 自己手动验证 fail2ban 是否真的在工作

最直接的办法：把**你自己的 IP 加进白名单**（这样不会被封），然后故意用错密钥登录几次，
再看 fail2ban 日志有没有识别到。

```bash
# 在服务器上：先把自己加白名单
fail2ban-client set sshd addignoreip <你的IP>

# 然后从你本机故意用错误密钥登录 3~4 次
ssh -i /path/to/wrong_key -p <SSH端口> root@<服务器IP> exit

# 回服务器看日志：出现 "Ignore <你的IP> by ip" 就说明识别成功
#（Ignore 是在正则匹配之后才记录的，所以有它 = 匹配成功）
tail -10 /var/log/fail2ban.log

# 测完记得把白名单去掉
fail2ban-client set sshd delignoreip <你的IP>
```

---

## 常用参数

### 开荒部分（`deploy-a.sh` 和 `deploy-b.sh` 都有）

| 参数 | 说明 | 默认 |
| --- | --- | --- |
| `--ssh-port <端口>` | 开荒后 SSH 使用的端口 | `20000-60000` 内随机 |
| `--ssh-key <公钥串>` | 写入 `authorized_keys` 的公钥 | 自动从 `~/.ssh/*.pub` 找（优先 `id_ed25519.pub`） |
| `--ssh-key-file <路径>` | 从文件读公钥 | 同上 |
| `--keep-ssh-port` | 不改 SSH 端口（只做其余加固） | 关 |
| `--skip-bootstrap` | 跳过开荒，只做第 2 步 | 关 |
| `--yes` | 开荒阶段不再交互确认（无人值守） | 关 |
| `--vps-sh <路径>` | 指定本地 `vps.sh` | 自动找同目录，找不到就从仓库下载 |

> `vps.sh` 不传参数时仍是**完全交互式**的，和以前一样。非交互参数是加法，不影响老用法。

### 第 2 步 · `deploy-a.sh`（入口端）

| 参数 | 说明 | 默认 |
| --- | --- | --- |
| `--domain` | **客户端要连的地址**：你的域名（需 A 记录指向 A）或 A 的公网 IP。详见上文专节 | 自动探测公网 IP |
| `--port` | 用户入口端口 | `443` |
| `--reverse-port` | B 反向隧道落点端口 | `20000-60000` 内随机 |
| `--nodes` | 节点数量，生成 `node1..nodeN`，各自独立 UUID | `1` |
| `--sni` | REALITY **伪装成**访问哪个站。**必须实测可用**，见下文专节 | `www.apple.com` |
| `--path` | XHTTP path | 自动生成随机路径 |
| `--pq` | 用 ML-KEM-768 后量子 VLESS Encryption | X25519 |
| `--dry-run` / `--force` / `--skip-firewall` / `--skip-install` | 见下文 | 关 |

### 第 2 步 · `deploy-b.sh`（出口端）

| 参数 | 说明 |
| --- | --- |
| `--token` / `--token-file` | 从 A 复制的登记令牌（推荐） |
| `--a-addr` / `--domain` | A 的域名或稳定 IP（不用令牌时必填） |
| `--reverse-port` `--bridge-uuid` `--encryption` `--reverse-domain` | 不用令牌时手动指定 |
| `--dry-run` / `--force` / `--skip-install` | 见下文 |

> `deploy-b.sh` **不再有 SSH 迁移选项**（原 `setup-b.sh` 的 `--ssh-port` / `--finalize-ssh`）。
> SSH 加固已经由第 1 步的开荒完成，留着那套「两阶段迁移」只会在已开荒的机器上制造把 22 重新打开的风险。

### 通用参数

| 参数 | 说明 |
| --- | --- |
| `--dry-run` | 只生成并校验配置、打印结果，不改动系统。不需要 root，且自动跳过开荒 |
| `--force` | 已存在部署时强制重做（会先备份）；同时表示「允许重新开荒」 |
| `--skip-firewall` | 不改动防火墙（仅 `deploy-a.sh`） |
| `--skip-install` | 不自动安装 Xray（假设已装） |

---

## 脚本替你做的事

**第 1 步 · 开荒（`vps.sh`，两台都跑）**

`apt upgrade` → 装 `wget`/`curl`/`openssh-server`/`rsyslog` → 时区 `Asia/Shanghai` →
下载并覆盖 `sshd_config`（`PasswordAuthentication no`、`PermitRootLogin prohibit-password`）→
改 SSH 端口、写入你的公钥 → 装并配置 fail2ban → `ufw` 重置为 `deny incoming` + 放行 SSH/80/443 →
journald 限 `30M`/3 天 → logrotate → 每周 `/tmp` 清理 cron。

**第 2 步 · A 侧**

1. 官方脚本安装 Xray-core，并校验 `x25519` / `uuid` / `vlessenc` 可用
2. 生成 REALITY 公私钥、每节点 UUID、`shortId`、XHTTP 随机 path、A↔B 的 VLESS Encryption 一对
3. 写 `/usr/local/etc/xray/config.json`：443 上 REALITY+XHTTP 用户入口 + 反向端口上的裸 RAW 反代入站
4. 放行 `443/tcp` 与反向端口（**不按 B 的 IP 设白名单**）
5. 落盘到 `/etc/xray-reverse/`：`state.env`、`secrets.env`(600)、`enroll-token.txt`、`client-links.txt`

**第 2 步 · B 侧**

1. 安装 Xray-core
2. 写配置：`inbounds` 为空，只有一条主动拨向 A 的 `tunnel` 出站 + `freedom` 出口
3. 写 `/etc/systemd/system/xray.service.d/restart.conf`（`Restart=always` / `RestartSec=5`）并 `enable`
4. 自动验证：服务 active、到 A 的 ESTAB、对外无多余监听、`inbounds` 为空
5. **不动防火墙**（没有入站端口需要放行）

**两者共同**

- 写配置走 **临时文件 + `xray -test` 校验 + 原子替换**
- 改动前备份原配置（`config.json.bak-<时间戳>`），重启失败**自动回滚**
- 端口占用检查、已有部署状态检查（避免误把已发出的客户端配置作废）

---

## ⚠️ 与原始教程的一处关键差异（重要）

原始教程里 A 的 `outbounds` 写的是：

```json
"outbounds": [ { "tag": "portal", "protocol": "vless", "settings": {} } ]
```

**这个写法在 Xray 26.x 上会直接启动失败：**

```
failed to build outbound config with tag portal >
VLESS settings: "vnext" should have one and only one member
```

原因：`reverse.portals` 里的 portal **会自己注册一个同名出站处理器**
（见 Xray 源码 `app/reverse/portal.go` 的 `Portal.Start()`），
不需要也不应该在 `outbounds` 里手写一个 vless 出站。

**正确做法**：`outbounds` 里只放一个 `freedom` 兜底，路由规则里照常引用 `"outboundTag": "portal"` 即可。
本脚本已按正确写法生成，并已用真实 Xray 26.3.27 跑通端到端。

---

## 验证清单

在 B 上：

```bash
systemctl is-active xray                              # active
RP=$(grep -oE '^REVERSE_PORT=.*' /etc/xray-reverse/state-b.env | cut -d= -f2)
echo "反向端口 = $RP"
ss -tnp | grep ":$RP"                                 # 看到指向 A 的 ESTAB
ss -ltnp                                              # 除 SSH 外无对外监听
```

在 A 上：

```bash
systemctl is-active xray                              # active
RP=$(grep -oE '^REVERSE_PORT=.*' /etc/xray-reverse/state.env | cut -d= -f2)
echo "反向端口 = $RP"
ss -ltnp | grep -E ":(443|$RP)"                       # 两个端口在监听
grep -i "$(ip route get 1 | awk '{print $7}')" /usr/local/etc/xray/config.json   # 应零命中
```

**别忘了确认你的 SSH 端口**（开荒改过，随机生成）：

```bash
cat /etc/xray-reverse/bootstrap.done      # 里面记着 ssh_port=...
```

客户端连上后访问 IP 查询站：**显示的出口 IP 必须等于 B 的实时公网 IP**。
如果显示的是 A 的 IP，说明路由没把用户流量送进 portal —— 检查路由里的 `user` 数组与 `email` 是否完全一致。

---

## 常见问题

**`--domain` 我该填什么？直接抄 `a.example.com` 行不行？**
不行。`example.com` 是国际标准里专门留给文档示例的域名，解析不到你的服务器，抄了必然连不上。
填你自己的域名（先加 A 记录指向 A 的公网 IP），或者干脆填 A 的公网 IP。详见上文专节。

**`--domain` 需要给域名申请 SSL 证书吗？需要先架个网站吗？**
都不需要。REALITY 不需要你的域名有证书，你的域名也不需要跑任何网站。
它唯一的作用是让客户端解析到 A 的 IP。证书那件事由 `--sni` 负责伪装。

**`--domain` 和 `--sni` 有什么区别？**
`--domain` 是**你要连的地址**（你的服务器），`--sni` 是**伪装成访问哪个网站**（比如苹果官网）。
前者跟你的机器绑定，后者跟你的机器毫无关系。看分享链接里 `@host:port` 和 `sni=` 就清楚了。

**能不能 A、B 两台同时一键装？**
不能。B 的令牌是 A 的产出，顺序是死的：**先 A，拿到令牌，再 B**。

**`--skip-bootstrap` 什么时候用？**
机器已经开荒过（比如你之前单独跑过 `vps.sh`，或者只想重装 Xray 部分）时用。
它会跳过第 1 步，直接用第 2 步部署。**只装 Xray 部分时记得自己确认防火墙和 SSH 加固已经做好了。**

**开荒为什么默认不重启了？**
`vps.sh` 原来跑完会问「要不要立即重启」。合并后如果在部署 Xray 之前重启，整个流程就断了。
所以 `deploy-*.sh` 调用它时固定加 `--no-reboot`。单独跑 `vps.sh` 时仍会问你要不要重启。

**SSH 端口我不记得了怎么办？**
开荒完成后写进了 `/etc/xray-reverse/bootstrap.done`：
```bash
grep ssh_port /etc/xray-reverse/bootstrap.done
```
或者直接看 sshd 生效端口：`sshd -T | grep -i '^port'`。

**反向端口为什么是随机的？能固定吗？**
`12345` 这种端口一眼就能猜到，容易被扫描器盯上。所以默认在 `20000-60000` 里随机挑，
挑的时候会避开入口端口、SSH 端口和已占用端口。挑好后写进令牌，B 自动同步。
想固定就用 `--reverse-port 23456`。

**重跑 `deploy-a.sh` 会不会换掉反向端口，把 B 搞断？**
不会。A 检测到已有 `/etc/xray-reverse/state.env` 时会**直接中止**，除非你显式加 `--force`。
加 `--force` 属于整机重做（新密钥、新客户端链接），此时反向端口会重新随机；重做后必须把新令牌重新交给 B。
另外随机挑端口时会避开「当前正被监听」的端口，所以不会误挑到旧实例还在用的那个口。

**B 换了公网 IP 要改配置吗？**
不用。隧道是 B 主动外拨到 A 的域名，A 侧不写死 B 的 IP、防火墙也不按 IP 放行。断线自动重连。

**为什么 B 上没有 `reverse-in` 入站？**
B 是 bridge，只做主动外拨。它不监听任何用户端口，公网扫不到 Xray。

**REALITY 握手失败 / 连不上？**
先确认回落域名可达且支持 TLS 1.3：

```bash
openssl s_client -connect www.microsoft.com:443 -tls1_3 </dev/null 2>&1 | grep -E 'Verify return code|Protocol'
```

注意：本机若装了 TUN 模式代理（Clash/Surge 等）会做 fake-IP DNS 劫持，
`www.microsoft.com` 可能被解析成 `198.18.x.x`，导致 REALITY 回落握手失败。
换一个不在劫持列表里的 `--sni` 域名，或换一台干净机器测试。

**想加节点？**
在 A 上重跑会作废已发出的链接。正确做法是编辑 A 的 `config.json`，
在 `user-in.settings.clients` 加一行新 UUID + `email`，再把该 `email` 加进路由的 `user` 数组，
然后 `xray -test -config` 校验并重启。B 侧完全不用动。

**`--force` 有什么用？**
重做部署。会生成全新密钥，**已发给客户端的分享链接全部失效**，需要重新分发。
对 `deploy-*.sh` 还额外表示「允许重新开荒」（否则检测到开荒标记会默认跳过）。

**手抄 VLESS Encryption 串报 panic？**
Xray 26.x 对畸形的 VLESS Encryption 串会直接 panic（`slice bounds out of range`，`infra/conf/vless.go`），
而不是给出可读报错。所以 `deploy-b.sh` 在写配置前会先校验该串的格式与长度，把 panic 变成一句可读提示。
仍然建议**直接复制 A 输出的令牌**，不要手抄这些长串。

---

## 验证记录

Xray 部分已在 **Xray-core 26.3.27** 上做过真实端到端验证（同机三实例模拟
`客户端 → A → 反向隧道 → B → Internet`）：

| 检查项 | 结果 |
| --- | --- |
| A / B 配置 `xray -test` | 通过 |
| B 主动拨 A，A 侧 portal 注册 mux worker | 通过 |
| 用户流量经 A 路由进 portal | 通过 |
| 出口流量由 B 的 `freedom` 出网 | 通过 |
| 端到端取回出口 IP | 通过（`via chain` == `direct`） |
| HTTPS / DNS 经链路可用 | 通过（HTTP 200） |
| B 侧对外无任何监听 | 通过 |
| 反向端口随机生成，且「令牌 / A 配置 / B 配置」三处一致 | 通过 |
| 随机端口端到端实跑（客户端 → A → 隧道 → B → 出网） | 通过 |
| `--reverse-port` 参数校验（非数字 / 越界 / 撞入口端口） | 通过（均正确报错退出） |
| 端口占用探测（`ss` 与 `netstat` 两条路径、含表头） | 通过 |

合并版新增验证：

| 检查项 | 结果 |
| --- | --- |
| `vps.sh` 非交互参数解析（`--ssh-port` / `--ssh-key` / `--ssh-key-file` / `--yes` / `--no-reboot`） | 通过 |
| `vps.sh` 无参数时保持原交互行为 | 通过（未改动原有分支） |
| **无可用终端时的守卫**（防止交互提示无限空转） | 通过（修复前 4 秒刷出 219215 行，修复后立即退出） |
| `deploy-a.sh` / `deploy-b.sh` 的 `--dry-run` 路径 | 通过 |
| 合并后令牌→A配置→B配置 端口一致性 | 通过 |
| 旧 `setup-*.sh` 自引用已全部清理 | 通过 |

### 真机验证（Debian 12 / Xray 26.3.27，2026-09-28）

在真实 VPS（Debian 12 bookworm, x86_64）上完整跑通，并做了同机三实例端到端：

| 检查项 | 结果 |
| --- | --- |
| 开荒（`vps.sh`）：SSH 改端口 / 禁用密码登录 / fail2ban / UFW / 日志优化 | 通过 |
| `deploy-a.sh` 全流程（含端口检查、随机端口、写配置、重启） | 通过 |
| REALITY 回落伪装（探测者看到的是真苹果证书） | 通过 |
| **REALITY 自检（`selftest_reality`）** | 通过 |
| 端到端：客户端 → A(REALITY+XHTTP) → 反向隧道 → B → 出网 | 通过（HTTPS 200，DNS 通） |
| B 侧零监听 | 通过 |
| 令牌 / A 配置 / B 配置 端口三处一致 | 通过 |
| **`www.microsoft.com` 作回落域名** | ❌ 失败（已改默认值，见上文专节） |

> 顺带记录：排查过程中发现并修复了两个只在真机才会暴露的问题 ——
> `ss` 表头导致端口误判（`check_port_free`）、以及上面的回落域名问题。
> 两者共同点是「表面全正常、实际不可用」，所以现在都加了真实验证环节。

---

## 安全约定

- REALITY 私钥、SSH 私钥、VLESS Encryption 私密材料**只留在服务器上**，不进聊天、不截图、不外发。
  交付给客户端的只有**公钥、UUID、shortId 和分享链接**。
- 只在你自己的两台机器之间搭建，**不要把 B 做成公开代理入口**。
- 开荒会禁用密码登录（`PasswordAuthentication no`）—— 这是有意的加固，
  但请务必先确认公钥正确。部署脚本不会改这些设置。
- 非空白环境：部署脚本只写 Xray 自己的配置，不会停掉或覆盖未知服务；检测到端口占用会直接中止并列出占用进程。

## 回滚

```bash
ls -t /usr/local/etc/xray/config.json.bak-* | head -1     # 找最近备份
cp /usr/local/etc/xray/config.json.bak-<时间戳> /usr/local/etc/xray/config.json
systemctl restart xray
```

SSH 配置的回滚（开荒会覆盖 `sshd_config`）：

```bash
ls -t /etc/ssh/sshd_config.backup.* | head -1
cp /etc/ssh/sshd_config.backup.<时间戳> /etc/ssh/sshd_config
sshd -t && systemctl restart ssh
```

## 卸载

```bash
# 只卸 Xray
bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ remove
rm -rf /etc/xray-reverse
rm -f /etc/systemd/system/xray.service.d/restart.conf
```

开荒部分（SSH 加固 / fail2ban / UFW / 日志策略）**没有自动卸载**，
因为它改动的是系统安全基线，自动回退反而更危险。需要的话手动处理：

```bash
# 恢复 SSH 配置（见上面「回滚」），然后
systemctl disable --now fail2ban
rm -f /etc/fail2ban/jail.local
rm -f /etc/rsyslog.d/49-vps-optimize.conf
rm -f /etc/systemd/journald.conf.d/size-limit.conf
rm -f /etc/logrotate.d/vps-optimize /etc/cron.weekly/vps-cleanup
ufw --force reset
```
