# inode-cli

Rust 编写的实验性 H3C SSL VPN 命令行客户端，目标平台为 Windows、Linux、macOS。直接实现 HTTPS 登录、`NET_EXTEND` 和 IPv4 TUN 数据转发，无需 OpenConnect 子进程。

Windows、Linux、macOS 的 x64 与 ARM64 共六个目标，都在 GitHub 托管 runner 上以管理员/root 跑过完整 CLI 系统测试：模拟网关登录、创建真实内核 TUN、经 TLS 完成 ICMP 往返、断开后回收接口与路由。但模拟网关不等于真实设备，这是实验性项目，真实 H3C 网关的端到端连通仍需自行验收。

## 构建

安装 Rust 1.92 或更新版本，运行：

```sh
cargo build --locked --release
cargo test --locked --all-targets
```

Linux 构建需要 C 编译器、pkg-config、OpenSSL 开发包；运行需要 `/dev/net/tun` 和 iproute2。Windows 构建需要 MSVC C++ 工具链；连接时将官方、与 CPU 架构匹配的 [wintun.dll](https://www.wintun.net/) 放在 inode.exe 旁（Release 的 Windows zip 已附带对应架构的 wintun.dll，解压即用）。macOS 使用系统 utun 和 route。建立接口及配置路由需要管理员/root 权限；probe、authenticate 不需要。

## 使用

```sh
inode doctor
inode probe https://vpn.example.com:443
inode authenticate https://vpn.example.com:443 --user your-account
inode connect https://vpn.example.com:443 --user your-account --route 10.20.0.0/16
inode captcha-test captcha.png
```

密码通过终端隐藏输入。自动化可用 `--password-stdin`，从受保护的秘密管理程序管道输入；不要将密码放在命令参数、脚本或 shell 历史中。

自签名网关使用经独立确认的 `--servercert <64位SHA256证书指纹>`，或对主机名有效的组织 CA 文件 `--ca organization-ca.pem`。指纹在每条实际 TLS 连接上、发送 HTTP 数据之前校验，不提供跳过验证开关。

网关要求图片验证码时，默认由内嵌 CNN 在本机自动识别，不联网、不调用第三方打码服务。识别置信度低于 `--captcha-confidence`（默认 0.90）时只重新抓图、不提交，因此错误提交最多 3 次即停止，避免账号锁定；两次抓图之间固定间隔 300 毫秒。模型权重 `src/captcha_model.bin` 随二进制静态链接，只针对目标网关的验证码样式训练，换一种样式需要重新训练。

`inode captcha-test <图片文件>` 对单张图片离线跑一次识别，输出「识别结果 + 置信度」，用于评估模型在你的网关上是否可用。

加 `--manual-captcha` 改回人工输入：交互终端直接以彩色字符显示图片，无需浏览器或图片查看器，使用 `--captcha-columns 80` 调整宽度（40–160 列），辨认后在当前会话输入验证码。可选 `--captcha-file captcha.png` 同时导出图片；重定向终端输出时必须指定该参数。文件必须尚不存在。

密码错误不自动重试——自动模式下重试只针对被网关判定为验证码错误的情况，密码或账号本身被拒会立即终止。短信、证书认证、动态口令、SSO 和密码变更流程尚未实现。

隧道断开后自动重连：复用已有会话 Cookie 重开隧道，不重新提交密码，接口和路由保持不变，退避从 1 秒起翻倍至上限 30 秒。`--reconnect-attempts`（默认 5）是连续失败的上限，成功一次即清零，设 0 则首次断开就退出。网关重连后若改派了不同的 IP，客户端中止而不是留下地址与接口不符的隧道。

空闲隧道靠 TCP keepalive 维持，`--keepalive`（默认 30 秒，0 关闭）同时设置空闲时间与探测间隔，用于避免 NAT 和防火墙静默回收连接，并探测对端已消失却没有发 FIN 的死链路。协议只定义了数据帧，没有可用的应用层心跳，所以保活只能做在 TCP 层。

网关在 `NET_EXTEND` 响应里下发分配地址、内网掩码和授权网段（`IPADDRESS`、`SUBNETMASK`、`ROUTES` 三个头），客户端总是把后两项打印出来，即使不采用——不必再向管理员索要内网 CIDR。默认仍然只安装明确指定的 `--route`；加 `--gateway-routes` 才会把网关下发的网段一并安装。无论来源，每条路由都要通过同一套校验：不得是默认路由、必须是网络地址、不得捕获 VPN 网关本身。无法解析的下发条目只提示不安装。

接口固定以 `/32` 建立，不因网关下发的掩码而自动纳入整个内网段。`--mtu`（默认 1400，范围 576–1500）是本地选择：协议不下发 MTU，1400 与 OpenConnect 的 H3C 实现取值一致。

连接持续前台运行，Ctrl+C 断开。退出时回收本次创建的路由和接口；不修改 DNS 或默认路由——协议里没有下发 DNS 的字段。强制终止或系统崩溃不保证完成用户态清理。

## 验证范围

测试覆盖 XML/表单转义、客户端验证码字段大小写、握手下发的掩码与路由解析（含主机位归一、非法条目隔离、越界掩码拒绝）、验证码模型权重形状与卷积/池化/旋转/缩放算子、跨源跳转拒绝、证书指纹拒绝且无 HTTP 数据泄漏、模拟 TLS 登录/会话 Cookie/隧道收发/注销、分片及合并帧、非法 IPv4 数据、三平台路由参数与失败回收。自动检查 src/tests/examples 下每个 Rust 文件均不超过 300 行。`examples/system_e2e.rs` 在管理员/root 环境运行完整 CLI，通过测试地址 192.0.2.2 的 ICMP 验证实际内核 TUN 与 TLS 数据路径，并断言退出后没有残留接口和路由；`examples/system_e2e.rs` 的路由完全来自网关下发的 `ROUTES`，装错或没装 ICMP 就不通。`examples/reconnect_e2e.rs` 让模拟网关掐断已建立的隧道，断言客户端复用会话 Cookie 重开隧道。`.github/workflows/system-e2e.yml` 在六个 OS/架构组合上运行这两个测试。模拟网关仍不证明真实设备协议兼容性。`doctor` 仅检查本地前提，不证明实际连通。

当前仅支持 IPv4，不支持后台服务。隧道只有 TLS 一条通道：H3C 官方 SSL VPN 白皮书与 OpenConnect 的实现都只描述 SSL 封装的 IP 接入，公开资料里没有可参考的 UDP/DTLS 通道，所以没有 UDP 加速。重连只覆盖隧道层：会话 Cookie 失效后仍需重新运行命令并输入密码。

协议研究参考 [OpenConnect H3C 草案 MR 397](https://gitlab.com/openconnect/openconnect/-/merge_requests/397) 及目标网关公开的协议发现和登录页面。此项目不是 H3C 官方 iNode 客户端。

## 许可

MIT，见 [LICENSE](LICENSE)。
