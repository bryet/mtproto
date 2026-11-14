# MTProto

当前仓库 `mtproxy.py` 的异步 Rust 重构，使用 Tokio。配置采用 `config.example.yaml` 的大写字段和模式开关，项目不依赖 Python 运行时。

## 构建和运行

需要 Rust **1.85 或更新版本**、C 编译器（HTTPS 依赖的 ring 构建需要），Linux/macOS 支持 TCP 和 Unix socket。

```bash
cd mtproto
cargo build --release --locked
cp config.example.yaml config.yaml

# 生成随机密钥，然后把输出填入 config.yaml 的 SECRET
./target/release/mtproto --generate-secret

# 只检查配置，不监听、不访问网络
./target/release/mtproto -c config.yaml --check-config

# 启动，前台运行并输出 Telegram 代理链接
./target/release/mtproto -c config.yaml
```

请在部署前更换示例 SECRET。监听端口还需由服务器防火墙/安全组放行；使用 443 等低端口需要相应系统权限。日志输出到 stderr，代理链接输出到 stdout。`RUST_LOG` 可覆盖配置日志级别。

## Docker 镜像与自动发布

`.github/workflows/release-build.yml` 通过 Actions 手动触发，输入 `latest`、`0.1.0`、`v0.1.0` 或 `0.1.0-rc.1`。工作流先构建 AMD64/ARM64 musl 静态二进制，再复用这些产物构建多架构 `scratch` 镜像，推送至 `ghcr.io/<owner>/<repository>`，同时发布二进制压缩包到 GitHub Release。

- 输入 `latest`：镜像标签 `latest`。
- 输入 `0.1.0` / `v0.1.0`：镜像标签 `0.1.0`、`latest`。
- 输入 `0.1.0-rc.1`：只推送预发布标签，不更新 `latest`。
- 使用工作流的 `GITHUB_TOKEN`，无需额外 Docker 密码；若已有同名 GHCR 包，需允许当前仓库的 Actions 写入该包。包的公开/私有状态由 GitHub Packages 设置决定。

镜像以 UID/GID `65532:65532` 运行，默认监听 8443。`docker-entrypoint` 是编译后的 Rust 二进制，而不是 shell 脚本，兼容 `scratch`。默认读取 `/etc/mtproto/config.yaml`；镜像中的配置只是示例，请部署前用自己的文件只读挂载覆盖，或显式设置环境变量。

入口支持 `SECRET`、`DOMAIN`、`TAG`：
- 未设置环境变量时完整保留 YAML 配置。
- `SECRET` 覆盖主密钥（32 个十六进制字符）。只设置 SECRET 时切换为 secure 模式。
- `DOMAIN` 设置 TLS_DOMAIN 并切换为 TLS-only；未设置 SECRET 时保留配置文件中的密钥，不注入固定密钥。
- `TAG` 覆盖 AD_TAG；未设置时保留 YAML 中的标签，显式传入空值可清除。
- `CONFIG_FILE` 可覆盖默认配置路径，`-c` / `--config` 的优先级更高。

覆盖只作用于内存，不调用 `sed`、不修改挂载文件，也不会误改 `SECRET_1` 等其他密钥。SIGUSR2 重载时重新读取 YAML 并再次应用容器环境变量。挂载文件需要允许 UID 65532 读取；不要把生产 SECRET 放入 Dockerfile 或构建上下文。

以下以已有的宿主机 `/root/test/config.yaml` 为例（与本项目示例相同的 YAML 字段）：

```bash
# 先修改 /root/test/config.yaml 中的 SECRET；镜像地址请替换成实际地址
docker run -d --name mtproto --restart unless-stopped \
  -p 8443:8443 \
  --mount type=bind,src=/root/test/config.yaml,dst=/etc/mtproto/config.yaml,readonly \
  ghcr.io/<owner>/<repository>:latest

# 仅检查配置，不开启代理或访问公网
docker run --rm \
  --mount type=bind,src=/root/test/config.yaml,dst=/etc/mtproto/config.yaml,readonly \
  ghcr.io/<owner>/<repository>:latest --check-config

# 在同一份配置上使用环境变量选择 Fake-TLS（SECRET 使用自己的密钥）
docker run -d --name mtproto-tls --restart unless-stopped \
  -p 8443:8443 \
  --mount type=bind,src=/root/test/config.yaml,dst=/etc/mtproto/config.yaml,readonly \
  -e SECRET=0123456789abcdef0123456789abcdef \
  -e DOMAIN=itunes.apple.com \
  ghcr.io/<owner>/<repository>:latest
```

容器没有 shell，也不需要 Python、OpenSSL 动态库或 QEMU。如需宿主机 443 端口，可使用 `-p 443:8443` 并将 Telegram 链接中的端口调整为 443。

本地构建也必须使用 musl 静态产物；为每个架构同时构建 `mtproto` 和 `docker-entrypoint`（`cargo build --release --locked --bins --target <musl-target>`），分别放在 `docker-dist/amd64/` 和 `docker-dist/arm64/` 下，然后运行：

```bash
docker buildx build --platform linux/amd64,linux/arm64 \
  -t ghcr.io/<owner>/<repository>:latest --push .
```

Dockerfile 只复制预构建二进制及公开配置示例，不重新编译 Rust。普通 glibc 动态链接的 `target/release/mtproto` 不能放入此 `scratch` 镜像。

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
- `src/server.rs` / `src/main.rs`：监听、双向转发、指标、CLI 与信号。

## 测试

```bash
cargo test --locked
cargo fmt --check
cargo clippy --locked --all-targets -- -D warnings
```

测试覆盖 AES 标准向量、YAML/旧格式、多 secret、模式禁用、时间戳、重放缓存、CRC/序号/过大帧、Fake-TLS 分片与握手/业务数据共包、quickack、广告标签、IPv4/IPv6 中间代理密钥、连接清理、localhost fallback 和模拟中间代理完整 CBC 握手，以及诊断日志清空、DNS 首地址失败回退、SO_BINDTODEVICE 回环网卡探测、TCP keepalive 参数、关闭/RST socket 控制、现有连接广告标签/读取超时重载、独立子进程中的文件描述符上限调整。

`tests/python_vectors.txt` 是从仓库原 Python 实现生成的确定性协议向量；Rust 测试逐字节对照。常规测试仅使用内存或 loopback，不连接 Telegram 或公网服务，不需要 Python。

重新生成参考向量（需要 Python cryptography）：

```bash
python3 -I tests/python_reference.py ../mtproxy.py tests/python_vectors.txt
```

协议测试不能替代真实 Telegram 客户端部署联调。上线前建议分别启用 classic、secure、TLS，以及配置 AD_TAG 后进行收发测试；当前没有宣称真实 Telegram 端到端或广告展示已验证。

## 许可

遵循仓库根目录 `../LICENSE` 的 GPL v2 许可；此项目来自同仓库 Python 实现的协议移植。
