# Claude 连接助手：首版范围

日期：2026-10-23。首版源代码已实现；交付验证状态以 README 和本次测试结果为准。尚未填写用户住宅代理凭据，也未启用本机防火墙规则。

## 已确认的需求与环境

- Windows 11 x64，已有 Veee HTTP 代理 `127.0.0.1:15236`。
- 将 Claude 网页版、Claude Code、Claude Science 和用户添加的 API 工具接入美国静态住宅代理。
- 用户提供的套餐截图标明支持 SOCKS5 / HTTP / HTTPS；首版使用 **HTTP CONNECT**，具体 HTTP 地址、端口、凭据和静态出口由用户本地填写。
- 用户要求阻断这些程序的本地直接出网。实现 Windows 防火墙按 `.exe` 路径阻断非回环出站，并在退出后保留规则。
- 当前没有证据能确定既往封禁原因；固定出口不能保证不被封禁。

## 实现链路

```text
内置专用浏览器 / Claude Code / Claude Science / 已配置的 API 程序
                            ↓
                 127.0.0.1:17861 助手代理
                            ↓
                 127.0.0.1:15236 Veee
                            ↓
                     HTTP 住宅代理
                            ↓
                         目标服务
```

连接助手只监听本机回环地址。两个上游连接按顺序建立，住宅认证仅发往住宅代理；失败时终止请求，没有直连或换出口回退。应用不更改 Windows 全局代理。

## 首版功能与取舍

1. 中文桌面配置、Windows 账户凭据加密、连接日志与手动出口检测。
2. 可填写预期静态出口 IP；手动检测不符时停止代理。没有持续 IP 监控。
3. Electron 内置专用浏览器，隔离 Cookie、固定代理、禁用 QUIC、限制 WebRTC 非代理 UDP。采用独立可执行文件，避免防火墙规则影响用户所有普通浏览器窗口；未实现指纹伪造。
4. Code 与 Science 使用明确代理环境启动。Code 另传本次代理设置；Science 已运行时提示保存工作并完整退出，不结束现有任务。
5. 自动发现已知客户端及部分当前运行的子进程，允许手动添加 API 程序。启用前列出影响路径，再通过 Windows 管理员授权应用规则。
6. 防火墙阻断所选路径的非回环 IPv4 / IPv6 / UDP 出站；读取有效策略确认状态。规则继续保留，提供界面恢复和独立恢复脚本。

## 保护边界

- 只覆盖选择的可执行路径；未知子进程、更新后的新路径和未选择的工具需要补充。
- Node / Python 等共享运行时的其他任务也会受影响。
- 回环流量保留。其他本机代理仍可被程序主动访问，因此此版不能保证程序只使用助手这一个代理。
- 代理参数本身不能阻止不遵循参数的程序直连；必须同时启用相应程序的防火墙保护。
- 不会自动分类整个系统内的 Claude 请求，也不提供全系统隧道。
- 登录页可能由默认浏览器打开，需要将授权链接复制到专用浏览器；嵌入式浏览器的真实第三方登录尚未实测。

## 验收标准与状态

| 标准 | 当前证据 |
| --- | --- |
| 流量依次经过 VPN 与住宅代理，目标不会收到代理认证 | 本地可控代理集成测试覆盖 |
| 上游拒绝、认证失败、停止服务时不回退直连 | 本地自动化测试覆盖 |
| 按程序阻断非回环出站且恢复只移除自己的规则 | 脚本生成及模拟 PowerShell 执行测试覆盖；实际系统执行待验证 |
| 界面与 IPC 可运行，配置保存，代理启动/停止 | Electron 冒烟检查覆盖 |
| 专用浏览器对外部目标选择固定代理、回环保留直连 | Electron session 代理解析检查覆盖 |
| 用户住宅出口、三个客户端真实请求、登录回调 | 待用户在本地填入住宅参数后验证 |

## 官方参考

- [Claude Code 网络配置](https://code.claude.com/docs/en/network-config)
- [Claude Science 企业网络配置](https://claude.com/docs/claude-science/corporate-networks)
- [Claude Science 网络要求](https://claude.com/docs/claude-science/network-requirements)
- [Claude Science 入门](https://support.claude.com/en/articles/16563838-get-started-with-claude-science)

用户视频参考：[Bilibili BV1JzJf6JEkB](https://www.bilibili.com/video/BV1JzJf6JEkB/)。仅取得标题、简介和公开试看画面，未取得完整内容，不将宣传内容当作防封效果证据。
