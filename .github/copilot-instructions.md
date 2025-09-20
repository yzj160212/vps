# Copilot Instructions for VPS Setup Project

## 项目概览

本项目为 Debian 12 VPS 一键优化配置脚本，核心文件为 `vps.sh`，旨在自动化安全加固、服务配置、日志优化等流程。脚本高度自动化，适用于新手和运维人员。

## 主要文件

- `vps.sh`：主配置脚本，包含所有自动化逻辑。
- `README.md`：简要说明，包含一键安装命令。
- `sshd_config`、`jail.local`：可下载的 SSH 和 fail2ban 配置模板。
- `vercel.json`：部署相关配置（如有 Web 入口）。

## 关键开发模式与约定

- **自动化交互**：脚本通过 Bash 交互获取 SSH 端口和公钥，自动验证输入合法性。
- **配置文件下载与回退**：优先下载远程配置，失败时自动回退本地安全配置。
- **服务重启与验证**：所有关键服务（SSH、fail2ban、rsyslog、UFW）均自动重启并验证状态，异常时终止脚本。
- **日志与磁盘优化**：针对低配置 VPS，自动配置日志轮转、清理、压缩，并定期通过 cron 任务清理空间。
- **安全加固**：默认禁止密码登录，仅允许公钥认证，fail2ban 自动防护暴力破解。
- **防火墙规则**：UFW 默认拒绝所有入站，仅开放 SSH/HTTP/HTTPS，端口由用户自定义。

## 典型开发/调试流程

- 修改 `vps.sh` 后，建议在本地 Debian 12 VPS 测试，确保所有服务均能正常启动。
- 远程配置文件（如 `sshd_config`、`jail.local`）需同步至 GitHub 仓库，脚本自动下载。
- 若需本地调试，建议注释掉 `set -e` 以便排查错误。
- 关键命令：
  - 一键安装：`bash <(curl -fsSL vps-yy.vercel.app)`
  - 手动运行：`sudo bash vps.sh`

## 代码风格与模式

- 所有 Bash 函数均以 `check_`、`configure_`、`restart_`、`main` 等前缀命名，便于维护。
- 交互提示采用彩色输出，便于用户区分信息、警告和错误。
- 失败自动终止，避免半配置状态。

## 外部依赖与集成

- 依赖系统包：`wget`、`curl`、`sudo`、`openssh-server`、`rsyslog`、`fail2ban`、`ufw` 等。
- 远程配置下载自 GitHub 仓库 `yzj160212/vps/main`。
- 日志轮转与清理通过 `logrotate` 和 cron 实现。

## 重要注意事项

- 所有配置均假定运行环境为 Debian 12，其他版本可能不兼容。
- SSH 端口和公钥需用户手动输入，脚本自动验证。
- 断开 SSH 前务必测试新端口连接，避免锁死。

---

如需补充说明或有特殊约定，请在本文件补充，或在 `README.md` 详细描述。
