# 安全说明

## 支持范围

当前支持的稳定系列为 0.1.x。安全问题应通过正式发布页所列规范仓库的 GitHub Security Advisory 私下报告；如果发行物没有提供可验证的规范仓库和私下报告入口，不应把它视为正式版本。不要在公开 Issue 粘贴账号、密码、令牌、Cookie、签名媒体 URL、日志或下载样本。

支持的最低平台为 Windows 10 1903 x64。WinHTTP 的 `WINHTTP_OPTION_DISABLE_SECURE_PROTOCOL_FALLBACK` 在该版本起可用；初始化该防护失败时网络会话直接失败，程序不在旧系统上静默放宽 TLS 策略。

本项目是非官方独立客户端，不隶属于 Sankaku，也未获得其运营方或内容权利人的授权、认可或背书。站点名称仅用于描述互操作对象。

## 凭据

- 用户名、密码与 Bearer Token 不写入 `settings.json`、任务篮、元数据、日志、命令行或 Git。
- 选择“本机保存”后，三者作为一个小型 JSON 载荷由 Windows DPAPI CurrentUser 加密，保存到 `Data/.credentials`；另一 Windows 用户或另一台机器不能直接解密。
- DPAPI 不防护已经控制当前 Windows 用户会话的恶意程序。便携目录、Windows 账号与磁盘仍应使用适当访问控制和加密。
- “清除本机凭据”只删除加密凭据，不删除任务和媒体；站点端令牌撤销需在站点提供的账号安全页面完成。
- DPAPI CurrentUser 不是跨机器备份格式。携带个人 `Data/` 搬到另一 Windows 用户或电脑后，加密文件会保留但不能解密，需要清除后重新登录；正式发行包绝不能包含任何用户的 `Data/.credentials`。

## 网络边界

- 元数据和登录只允许 `https://sankakuapi.com`，禁止重定向。
- 页面浏览只允许精确的 Sankaku 官方 HTTPS 主机；带用户名、密码、非 443 端口或敏感查询键的地址会被拒绝。
- 媒体请求不携带 Authorization 或账号 Cookie；每次跳转都重新检查官方媒体域。
- API、媒体和缩略图使用独立的同步 WinHTTP 请求边界：禁用自动跳转、Cookie、自动认证和环境代理，HTTPS 仅允许 TLS 1.2，由 Windows Schannel 完成系统信任链、主机名和证书吊销验证；Qt TLS 后端也强制为 Schannel。
- 用户若配置代理，只接受一个不带凭据的显式 CERN HTTP 代理；它可通过 CONNECT 承载 HTTPS 目标，但不支持 SOCKS、PAC/WPAD 或 HTTPS-to-proxy，配置不受支持时直接拒绝而不会静默直连。
- Schannel 的在线证书吊销检查可能按照服务器证书链中的 Authority Information Access/CRL Distribution Points 访问 CA 的 OCSP/CRL 基础设施。因此“官方主机白名单”约束的是应用 HTTP 请求目标；Windows 信任服务为验证证书而产生的吊销查询是额外的系统级出站流量。
- 401/403 不重试撞击；429 遵守服务端冷却；5xx/连接错误只做有界、可取消退避。
- 自动测试在发现测试前阻断生产 WinHTTP bindings、socket 与 urllib 外联，CI 不验证真实登录；WinHTTP 单测只使用可注入的内存 fake。

## 文件边界

- 任务篮和设置使用同目录临时文件、`fsync` 和 `os.replace`。
- 下载只写用户选择目录下的规范作品 ID 文件名；未完成内容保留为 `.part`，成功后才原子替换。
- 媒体最大 50 GiB；缩略图最大 20 MiB；任务最多 10,000 项；搜索每页最多 40 项。
- 程序没有删除下载媒体的入口。移除任务只改 `Data/tasks.json`。
- 默认 `Downloads` 在设置中使用相对于当前便携根目录的值，整目录搬移时随新根解析；用户明确选择的外部绝对目录不会被程序擅自改写。
- `Data/.app.lock` 将同一便携目录限制为单实例，以保护任务篮和下载终态。不同副本可独立运行；不要删除活动锁或从多人共享目录并发运行。

## 已知限制

- 站点没有为本项目提供公开、稳定的第三方 API 合同；域名、OIDC、字段、限流和条款可能随时变化。
- Python 源码与便携 Runtime 若位于其他进程可写目录，会形成代码执行风险。正式分发应生成 SHA-256 清单、第三方许可证/SBOM，并考虑代码签名。
- 发布者必须从干净 staging 运行 `portable_self_check.py --release`。该模式只读检查 Python 3.13 x64 embedded 布局、锁定版本、Qt WebEngine 文件、许可证/SBOM 哈希、绝对构建路径和私有/生成内容；普通自检会创建可写 probe，不能替代发布门禁。
- `SHA256SUMS.txt` 排除 `Data/`、`Downloads/` 和清单自身，避免把私有内容纳入发行物；清单仍需通过可信发布渠道或签名保护。Runtime 来源、哈希和许可材料见 `PORTABLE_BUILD.md` 与 `THIRD_PARTY_NOTICES.md`。
- 内嵌 Qt WebEngine 是独立 Profile，但不是强安全沙箱；不要在其中登录无关站点或导入浏览器资料。
- 本项目不实现 CAPTCHA、Passkey、2FA 或年龄验证自动化；出现这些流程时由用户在官方界面处理。
