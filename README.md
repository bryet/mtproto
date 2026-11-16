# MTProto

基于 Python `mtproxy.py` 实现的异步 Rust 重构，使用 Tokio。配置采用 `config.example.yaml` 的大写字段和模式开关，项目不依赖 Python 运行时。

## 构建和运行

需要 Rust **1.85 或更新版本**、C 编译器（HTTPS 依赖的 ring 构建需要），Linux/macOS 支持 TCP 和 Unix socket。

```bash
# 在项目根目录运行
cargo build --release --locked --bin mtproto
cp config.example.yaml config.yaml

# 生成随机密钥，然后把输出填入 config.yaml 的 SECRET
./target/release/mtproto --generate-secret

# 只检查配置，不监听、不访问网络
./target/release/mtproto -c config.yaml --check-config

# 启动，前台运行并输出 Telegram 代理链接
./target/release/mtproto -c config.yaml
```

请在部署前更换示例 SECRET。监听端口还需由服务器防火墙/安全组放行；使用 443 等低端口需要相应系统权限。日志输出到 stderr，代理链接输出到 stdout。`RUST_LOG` 可覆盖配置日志级别。

## 二进制发布

`.github/workflows/release-build.yml` 构建 Linux AMD64/ARM64 的 musl 二进制，并将压缩包发布到 GitHub Release。

### 触发方式

- **手动运行**：在 Actions 中选择 **Build and Release**，填写 `version`，例如 `0.1.0`、`v0.1.0` 或 `0.1.0-rc.1`。
- **手动输入 `latest`**：读取 `Cargo.toml` 的包版本，例如 `0.1.0`，发布为 `v0.1.0`；不会创建名为 `latest` 的 Release。
- **推送标签**：推送 `v*` 标签时自动构建，标签应使用有效 Rust 版本，例如 `v0.1.0`。
- **清理缓存**：手动运行和标签推送均在 `release` 任务结束后自动删除仓库的所有 Actions 缓存，不再提供 `clear_cache` 开关。发布失败或被跳过时也会尝试清理；不删除 Actions 构建产物或 Release 附件。清理范围包含其他工作流的缓存，后续构建可能需要重新下载依赖和编译。

工作流先校验版本格式（例如 `0.1.0`、`0.1.0-rc.1`；不接受带前导零的数字段、路径或换行），再在 Runner 工作目录同步更新 `Cargo.toml` 和 `Cargo.lock` 的根包版本，不提交或推送修改。构建使用 `--locked --bin mtproto` 并检查产物没有动态加载器或共享库依赖；缺失二进制、配置示例、服务单元、安装脚本或发布压缩包时会报错。包含连字符的版本会标记为预发布。发布使用 `GITHUB_TOKEN`，写入权限仅授予发布及缓存清理 Job。工作流串行执行，防止清理缓存与另一次发布构建相互干扰。

### 发布产物

| 平台 | 文件名示例 |
| --- | --- |
| Linux AMD64 | `mtproto-x86_64-unknown-linux-musl-v0.1.0.tar.gz` |
| Linux ARM64 | `mtproto-aarch64-unknown-linux-musl-v0.1.0.tar.gz` |

每个压缩包包含以下文件，直接放在压缩包根目录：

| 文件 | 用途 |
| --- | --- |
| `mtproto` | 对应架构的静态链接二进制，具有执行权限 |
| `config.example.yaml` | YAML 配置示例，部署前必须更换 SECRET |
| `mtproto.service` | systemd 服务单元，使用 `/var/mtproto/config.yaml` |
| `mtproto.sh` | Bash 交互式安装与管理脚本，具有执行权限 |

从 GitHub Releases 下载适合服务器架构的压缩包后，在下载目录执行。下方版本号只是示例，请替换为实际下载的版本：

```bash
# ARM64 请替换为 aarch64 对应的文件名
ARCHIVE="$PWD/mtproto-x86_64-unknown-linux-musl-v0.1.0.tar.gz"
RELEASE_DIR="$(mktemp -d)"
tar -xzf "$ARCHIVE" -C "$RELEASE_DIR"
cd "$RELEASE_DIR"
cp config.example.yaml config.yaml

# 生成随机密钥，再将输出填入 config.yaml 的 SECRET
./mtproto --generate-secret
./mtproto -c config.yaml --check-config
./mtproto -c config.yaml
```

也可以直接指定已有配置文件：

```bash
./mtproto -c /etc/mtproto/config.yaml --check-config
./mtproto -c /etc/mtproto/config.yaml
```

程序默认读取当前工作目录的 `config.yaml`，可用 `-c` / `--config` 指定路径。端口、密钥、TLS 域名和广告标签均在 YAML 中设置；程序不使用环境变量覆盖 YAML 配置。日志级别仍可通过 `RUST_LOG` 覆盖。

## 安装与服务管理

### 使用交互式脚本

解压发布包后执行：

```bash
sudo bash ./mtproto.sh
```

已登录 root 账号时可直接使用 `bash ./mtproto.sh`。请将脚本保留在 `/var/mtproto` 以外的持久目录中，方便后续管理；上面的临时解压目录可能被系统清理。

- **要求**：Linux AMD64/ARM64、root 权限和 Bash。脚本当前支持 Ubuntu、Debian、Kali、CentOS、Fedora、AlmaLinux、Rocky Linux、Oracle Linux、Alpine。除 Alpine 使用 OpenRC 外，其余系统需要正在运行的 systemd；仅安装了这些发行版的容器不一定能使用服务管理功能。
- **依赖**：首次安装时检查并安装 `wget`、`curl`、`tar`、`gzip`，还需要系统基本命令。Alpine 默认没有 Bash 时，先执行 `apk add bash`；OpenRC 的 `rc-service`、`rc-update` 和 `supervise-daemon` 也需要可用。安装缺失依赖时会先运行包管理器更新命令，RPM 系统的 `dnf update` / `yum update` 可能升级已有软件包。
- **菜单**：`1` 安装、`2` 卸载、`3` 更新、`4` 启动、`5` 停止、`6` 重启、`7` 修改配置、`8` 查看链接、`9` 查看日志、`0` 退出。
- **安装**：脚本从 GitHub 获取最新正式 Release，并重新下载对应架构的压缩包，不直接使用解压目录里的二进制；因此需要访问 GitHub。首次配置依次选择端口、密钥模式和广告标签。端口范围为 `10000–65535`，留空随机生成；密钥模式默认选择 TLS，默认伪装域名为 `itunes.apple.com`，基础 SECRET 由二进制随机生成；AD_TAG 留空禁用。安装成功启动服务后启用开机自启，脚本不会自动放行防火墙端口。
- **更新**：菜单 `3` 更新二进制，并在 systemd 系统同步服务单元；下载和解压成功后才停止服务，更新完成后重新启动。保留 `config.yaml` 和 `mtp_info`，不会自动更新正在使用的管理脚本。GitHub 的 `releases/latest` 不包含预发布，指定版本或预发布请手动下载部署。
- **卸载**：确认后停止服务、禁用自启、删除服务文件和整个 `/var/mtproto`，包括配置、版本与链接信息；请提前备份需要保留的数据。

安装目录与管理文件：

| 路径 | 用途 |
| --- | --- |
| `/var/mtproto/mtproto` | 二进制程序 |
| `/var/mtproto/config.yaml` | 实际运行配置，首次创建权限为 `600` |
| `/var/mtproto/mtp_info` | 脚本显示链接使用的 IP、端口、客户端密钥和标签 |
| `/var/mtproto/version` | 已安装的 Release 标签 |
| `/etc/systemd/system/mtproto.service` | systemd 服务单元 |
| `/etc/init.d/mtproto` | Alpine 上由脚本生成的 OpenRC 服务脚本 |

程序始终以 `config.yaml` 为准，`mtp_info` 不是程序配置。若绕过菜单手动修改配置，脚本显示的链接信息不会自动同步；可从程序启动日志获取实际链接。`mtp_info` 中也有密钥，应限制文件访问权限。

### 手动安装 systemd 服务

以下命令在已解压的发布目录执行，需要 root 权限。随包的服务单元以 **root** 用户/组运行，工作目录为 `/var/mtproto`，异常退出后等待 5 秒重启；它不是非特权或沙箱化部署。

```bash
sudo mkdir -p /var/mtproto
sudo install -m 755 ./mtproto /var/mtproto/mtproto

# 仅在配置不存在时复制示例，不覆盖已有配置
if ! sudo test -e /var/mtproto/config.yaml; then
    sudo install -m 600 ./config.example.yaml /var/mtproto/config.yaml
fi

# 必须先更换 SECRET，再按需设置端口、模式、TLS_DOMAIN、AD_TAG 等
sudo editor /var/mtproto/config.yaml
sudo /var/mtproto/mtproto -c /var/mtproto/config.yaml --check-config
```

若没有 `editor` 命令，请使用已安装的文本编辑器。配置检查通过后再安装服务并启动：

```bash
sudo install -m 644 ./mtproto.service /etc/systemd/system/mtproto.service
sudo systemctl daemon-reload
sudo systemctl enable --now mtproto.service
sudo systemctl status mtproto.service
```

常用管理命令：

```bash
sudo systemctl restart mtproto.service
sudo systemctl stop mtproto.service
sudo systemctl disable mtproto.service

# 运行日志和启动时输出的代理链接
sudo journalctl -u mtproto.service -n 100 --no-pager
sudo journalctl -u mtproto.service -f

# 修改配置后重载；监听地址/端口变更仍需重启
sudo systemctl kill --kill-whom=main --signal=SIGUSR2 mtproto.service
```

手动安装不生成脚本的 `mtp_info` 和 `version`，请直接使用 systemd 和 YAML 配置管理。更新二进制前应停止服务，保留现有配置；如果同时更新服务单元，执行 `systemctl daemon-reload` 后再启动。

### Alpine / OpenRC

交互式脚本会生成 OpenRC 服务，不使用 `mtproto.service`。常用命令：

```bash
rc-service mtproto status
rc-service mtproto restart
rc-service mtproto stop
rc-update add mtproto default
rc-update del mtproto default
tail -f /var/mtproto/log_mtproto
```

systemd 部署日志在 journal 中；脚本生成的 OpenRC 服务将 stdout/stderr 写入 `/var/mtproto/log_mtproto`。日志可能包含客户端 IP 和代理密钥/链接，不应公开。

## 配置格式

```yaml
LOG_LEVEL: "info"
PORT: "8443"
SECRET: "0123456789abcdef0123456789abcdef"
MODES_CLASSIC: false
MODES_SECURE: true
MODES_TLS: false
# TLS_DOMAIN: "itunes.apple.com"
# AD_TAG: "0123456789abcdef0123456789abcdef"
```

原始示例文件采用 `KEY = VALUE`，不是标准 YAML。本项目将示例改为 `KEY: VALUE`，并兼容原来的等号写法。SECRET/AD_TAG 应使用引号，避免 YAML 将全数字密钥作为数字解析；端口兼容数字及字符串。

默认值按指定示例：8443 端口、仅 secure 开启。关闭所有模式时，与 Python 行为一致，回退到 TLS-only。TLS_DOMAIN 未配置时为 Python 默认值 `www.google.com`；要用其他域名，请显式配置。

### 模式与转发

| 字段 | 作用 |
| --- | --- |
| `MODES_CLASSIC` | abridged/intermediate 客户端传输，链接使用原始 SECRET |
| `MODES_SECURE` | padded intermediate 传输，链接密钥前缀 `dd` |
| `MODES_TLS` | Telegram Fake-TLS 外层认证与记录封装，链接密钥为 `ee` + SECRET + 域名十六进制 |
| `TLS_DOMAIN` | Fake-TLS 链接中的域名及默认 MASK_HOST |
| `AD_TAG` | 16 字节广告标签；配置后默认启用中间代理 |
| `USE_MIDDLE_PROXY` | 显式覆盖是否使用 Telegram 中间代理 |
| `FAST_MODE` | 直连回程复用客户端密钥，省去回程重复加解密，默认 true |

**Fake-TLS 是原程序的 TLS 外观封装，不是真正的标准 TLS 终止或证书加密。** 真正的 MTProto 内容仍由 Telegram 客户端协议保护。频道广告是否展示取决于 Telegram 对标签/账号的支持，不由代理保证。

### 兼容可选字段

- 多用户密钥：`SECRET`、`SECRET_1` … `SECRET_99`，相同密钥去重。
- 监听：`LISTEN_ADDR_IPV4`（`0.0.0.0`）、`LISTEN_ADDR_IPV6`（`::`）、`LISTEN_UNIX_SOCK`（空）。地址设置为空字符串可禁用对应监听器，IPv6 使用 v6-only，避免双栈端口冲突。
- 代理链接：`MY_DOMAIN`（空时自动使用公网 IP；无法探测时显示 `YOUR_IP`）。
- 未认证连接转发：`MASK`（true）、`MASK_HOST`（TLS_DOMAIN）、`MASK_PORT`（443）。定期探测该站点的 TLS 1.3 加密证书记录长度，失败保留随机长度；DNS 缓存约 90 秒。首次解析会尝试全部 DNS 地址，直到连接成功或整个连接期限到达；转发结束时显式关闭远端写方向，远端结束或关闭失败等场景设置客户端立即 RST。
- 上游地址族：`PREFER_IPV6`（直连默认 true，中间代理默认 false），IPv6 不可达时尝试 IPv4。
- 反向代理：`PROXY_PROTOCOL`（false），支持 HAProxy v1/v2。**只应在可信反向代理后开启**，否则客户端可伪造来源地址。Unix socket 可配合该选项传递真实地址。
- 重放与地址缓存：`REPLAY_CHECK_LEN`（65536）、`CLIENT_IPS_LEN`（131072）；0 禁用相应缓存。`IGNORE_TIME_SKEW`（false）控制 Fake-TLS 时间校验。
- 超时（秒）：`CLIENT_HANDSHAKE_TIMEOUT`（默认在 5–14 秒中随机选择，包括未认证 fallback）、`TG_CONNECT_TIMEOUT`（10）、`TG_READ_TIMEOUT`（60）、`CLIENT_KEEPALIVE`（600，空闲时间与探测间隔均使用此值）、`CLIENT_ACK_TIMEOUT`（300，Linux TCP_USER_TIMEOUT）。
- 后台周期（秒）：`STATS_PRINT_PERIOD`（600）、`PROXY_INFO_UPDATE_PERIOD`（86400）、`GET_CERT_LEN_PERIOD`（默认随机选择 14400–21599 秒，即 4–6 小时）。
- 缓冲：`TO_TG_BUFSIZE`（65536）、`TO_CLT_BUFSIZE`（`[16384, 100, 131072]`）。三元素列表表示 `[低容量, 连接数阈值, 高容量]`。
- 公网地址：`PUBLIC_IPV4`、`PUBLIC_IPV6`（可选新增字段），用于 NAT 场景中间代理派生密钥及生成链接。不填写时启动时分别探测两种地址族；Linux 遍历 `eth`/`ens`/`enp` 网卡并使用 `SO_BINDTODEVICE` 绑定实际探测 socket，随后尝试默认路由作为后备。端点沿用 Python 的 HTTP 公网地址服务；无绑定网卡权限时可以使用默认路由后备或手工指定公网地址。仅公网探测失败时会降级直连并记录警告，与 Python 原理一致；配置了公网地址但中间代理不可达时，不静默移除广告路径。

未知字段会报错，防止拼写错误悄悄使用默认值。无效 SECRET/AD_TAG 会拒绝启动，不沿用 Python 将坏密钥自动截断/补零的做法。

### Prometheus 指标

```yaml
METRICS_PORT: 9090
METRICS_LISTEN_ADDR_IPV4: "127.0.0.1"
METRICS_LISTEN_ADDR_IPV6: "::1"
METRICS_WHITELIST: ["127.0.0.1", "::1"]
METRICS_PREFIX: "mtproxy_"
METRICS_EXPORT_LINKS: false
```

```bash
curl http://127.0.0.1:9090/metrics
```

不配置 METRICS_PORT 时禁用指标服务。白名单默认 loopback（Python 当前代码存在空白名单默认值，本版本采用其预期的本地白名单）。`METRICS_LISTEN_ADDR_IPV4` 缺省值保留 Python 的 `0.0.0.0`，建议按示例绑定回环地址。

保留总连接、坏连接、握手超时、分段连接时长计数，以及每个 secret 的当前连接、累计连接、上下行字节和消息计数。直连模式中的消息计数与原程序一样是读块数，中间代理模式是协议消息数。用户标签包含 secret，`METRICS_EXPORT_LINKS` 还会暴露代理链接；不要公开指标端点。

### 客户端诊断与资源上限

每次统计周期输出新客户端 IP、按 IP 累计的重复握手次数、客户端时间偏差分钟数，以及各用户连接/流量/消息统计。输出后清空本周期事件；IP 去重缓存继续保留。诊断事件各类别上限为 131072 个 IP，避免未认证流量导致无限内存增长。关闭 `CLIENT_IPS_LEN` 会禁用新 IP 日志，但不会关闭重复握手和时间偏差日志。

Unix 平台在正常启动时自动将 `RLIMIT_NOFILE` 软上限提高到已有硬上限，失败记录警告并继续运行。不修改硬上限；`--check-config` 不调整资源限制。`SIGUSR1` 也可触发客户端诊断输出。日志包含客户端 IP、用户标签包含 secret，应限制日志访问权限。

### 信号

- `SIGUSR2`：重新加载原配置路径，新连接使用新设置；已有中间代理连接每个后续请求使用当前 `AD_TAG`，已有上游转发在下一次读取时使用当前 `TG_READ_TIMEOUT`。当前正在等待的读取不被重新计时，既有连接的协议和密钥不变。监听端口/地址变化会拒绝重载，需要重启；日志级别变化也需重启。后台周期配置在下一轮读取时生效。
- `SIGUSR1`：打印当前连接状态和本周期客户端诊断（替代 Python 交互式 pdb）。
- `SIGINT` / `SIGTERM`：关闭监听器、后台任务和连接。

运行中修改 PUBLIC_IPV4/PUBLIC_IPV6 会更新其显式指定值；删除该字段后需要重启以重新探测。运行时无需 Python 的 uvloop、可选加密模块和连接池适配层（原连接池默认容量为 0）。程序自动提升文件描述符软上限，但硬上限仍由部署环境控制，可使用 systemd `LimitNOFILE=65536` 或合适的 `ulimit -n`。

## 实现结构

- `src/config.rs`：YAML/等号兼容解析、类型与边界校验。
- `src/crypto.rs`：AES-256 CTR/CBC、SHA-256/HMAC、系统安全随机数。
- `src/wire.rs`：TCP/Unix/in-memory 的分层流、Fake-TLS 记录与加密缓冲。
- `src/auth.rs`：客户端认证、重放检测、PROXY protocol、未认证转发。
- `src/protocol.rs`：三种 MTProto 传输帧、RPC CRC/序号/CBC 对齐、广告请求与 quickack。
- `src/upstream.rs`：Telegram DC 直连、fast-mode、中间代理密钥与握手。
- `src/state.rs`：配置快照、有界缓存、统计和连接计数自动清理。
- `src/maintenance.rs`：官方中间代理列表/密钥更新、证书记录探测、统计和诊断日志。
- `src/discovery.rs`：按 Linux 网卡绑定的 IPv4/IPv6 公网地址探测。
- `src/system.rs`：Unix 文件描述符资源上限调整。
- `src/server.rs`：监听、双向转发、指标与信号。
- `src/cli.rs` / `src/main.rs`：命令行参数、配置加载与程序入口。
- `mtproto.service`：固定 `/var/mtproto` 路径的 systemd 服务单元。
- `mtproto.sh`：交互式安装、更新、卸载、配置和服务管理。
- `.github/workflows/release-build.yml`：双架构 musl 构建、打包、Release 发布和发布后的全量 Actions 缓存清理。

## 测试

```bash
cargo test --locked
cargo fmt --check
cargo clippy --locked --all-targets -- -D warnings
```

当前保留 `src/` 内的单元测试，覆盖 AES 标准向量、YAML/旧格式、多 secret、时间戳与重放缓存、帧 CRC/序号/长度校验、Fake-TLS 记录分片、quickack、广告请求、连接清理、localhost fallback、诊断日志、DNS 地址回退、Linux 网卡绑定、TCP keepalive、读取超时与广告标签热重载，以及子进程中的文件描述符上限调整。

原 `tests/` 集成测试目录和 Python 参考向量已移除，当前测试不依赖 Python。测试使用内存流、本地回环连接或隔离子进程，不连接 Telegram 或公网服务。

协议测试不能替代真实 Telegram 客户端部署联调。上线前建议分别启用 classic、secure、TLS，以及配置 AD_TAG 后进行收发测试；当前没有宣称真实 Telegram 端到端或广告展示已验证。

## 许可

`Cargo.toml` 声明许可证为 `GPL-2.0-only`，即 GNU GPL v2；本项目由 Python MTProto 代理实现移植而来。
