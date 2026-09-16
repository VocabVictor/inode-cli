# inode-cli

Rust 编写的实验性 H3C SSL VPN 命令行客户端，目标平台为 Windows、Linux、macOS。直接实现 HTTPS 登录、`NET_EXTEND` 和 IPv4 TUN 数据转发，无需 OpenConnect 子进程。

已在 Windows x64、Linux x64 编译并通过本地网关/TLS/TUN 系统测试；macOS 仅通过双架构编译检查，未做实机验证。这是实验性项目，真实网关的端到端连通仍需自行验收。

## 构建

安装 Rust 1.92 或更新版本，运行：

```sh
cargo build --locked --release
cargo test --locked --all-targets
```

Linux 构建需要 C 编译器、pkg-config、OpenSSL 开发包；运行需要 `/dev/net/tun` 和 iproute2。Windows 构建需要 MSVC C++ 工具链；连接时将官方、与 CPU 架构匹配的 [wintun.dll](https://www.wintun.net/) 放在 inode.exe 旁。macOS 使用系统 utun 和 route。建立接口及配置路由需要管理员/root 权限；probe、authenticate 不需要。

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

连接持续前台运行，Ctrl+C 断开。只添加明确指定的 `--route`，退出时回收本次创建的路由和接口；不修改 DNS 或默认路由。目标内网 CIDR 需由管理员提供，不能仅凭 VPN 公网地址推断。拒绝覆盖 VPN 网关本身的路由。强制终止或系统崩溃不保证完成用户态清理。

## 验证范围

测试覆盖 XML/表单转义、客户端验证码字段大小写、验证码模型权重形状与卷积/池化/旋转/缩放算子、跨源跳转拒绝、证书指纹拒绝且无 HTTP 数据泄漏、模拟 TLS 登录/会话 Cookie/隧道收发/注销、分片及合并帧、非法 IPv4 数据、三平台路由参数与失败回收。自动检查 src/tests/examples 下每个 Rust 文件均不超过 300 行。`examples/system_e2e.rs` 在管理员/root 环境运行完整 CLI，通过测试地址 192.0.2.2 的 ICMP 验证实际内核 TUN 与 TLS 数据路径。模拟网关仍不证明真实设备协议兼容性。`doctor` 仅检查本地前提，不证明实际连通。

当前仅支持 IPv4；不自动应用网关下发的路由/DNS，不支持断线重连、后台服务和 UDP 加速。内核接口、路由和真实内网连通仍需逐平台验收。

协议研究参考 [OpenConnect H3C 草案 MR 397](https://gitlab.com/openconnect/openconnect/-/merge_requests/397) 及目标网关公开的协议发现和登录页面。此项目不是 H3C 官方 iNode 客户端。

## 许可

MIT，见 [LICENSE](LICENSE)。
