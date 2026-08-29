# SankakuSyncer Portable

面向 Windows x64 的 Sankaku Channel 本地浏览与受控下载工具。它借鉴现有便携应用的可迁移启动、严格 URL 边界、DPAPI 本机凭据、可恢复任务篮和 `.part` 原子下载模式，但没有复制任何参考项目的账号、Cookie、缓存、日志或媒体。

系统要求：Windows 10 1903（64 位）或更高版本。该下限来自 WinHTTP 的显式 TLS 降级防护选项；在更旧的 Windows 上程序会失败关闭，不会降低网络安全设置继续运行。

本项目是非官方的独立客户端，与 Sankaku、其运营方及内容权利人不存在隶属、授权、认可或背书关系；项目名称和站点名称仅用于说明兼容对象。

> 只访问和保存你有权使用的内容。项目不会自动处理 CAPTCHA，不会绕过年龄、会员、地域或内容权限，不会轮换身份、代理、User-Agent 或 API 主机。Sankaku 没有为本项目提供或承诺第三方 API；站点行为和许可可能变化，使用前请自行核对 [服务条款](https://legal.sankakucomplex.com/terms-of-service)。

![SankakuSyncer 发现与搜索界面](docs/SankakuSyncer_UI.png)

## 0.1.1 功能

逐版变化见 [CHANGELOG.md](CHANGELOG.md)。

本版修复：

- 搜索请求可随时取消；翻页结果和游标只在整页成功后一起提交，取消或失败不会留下半页状态。
- 单项作品遇到 403 时只标记该项失败并继续处理同批任务，不再阻断整批。
- TaskStore 恢复态回写失败时保留原任务文件并报告错误，不会把可读任务误隔离为损坏文件。
- 持久凭据升级为 schema 2：DPAPI 载荷不再保存密码；设置与加密会话写入失败时会恢复旧状态，恢复本身异常时明确告警。

- 原生发现与标签搜索：默认 `rating:safe`，只有用户主动选择时才请求其他分级；每页 8–40 项，游标原样分页。
- 图片网格：缩略图最多双并发、20 MiB 上限、官方 HTTPS 媒体域白名单；双击可在站内页打开。
- 受限站内浏览：只允许 Sankaku 官方 HTTPS 页面，不接受带账号信息或令牌参数的 URL；禁止弹窗和网页直接下载。
- 任务篮：作品 ID 去重、10,000 项硬上限、原子 JSON、revision 防多实例静默覆盖；异常退出后排队/运行任务恢复为待处理。
- 单实例：同一个便携目录一次只允许运行一个进程，避免任务篮与下载终态被两个窗口竞争写入；不同目录副本彼此独立。
- 登录：用户名和密码只发往 `https://sankakuapi.com/auth/token`；令牌与密码不进入普通设置、日志或命令行。本机保存时仅用 Windows DPAPI CurrentUser 加密用户名和令牌，不持久化密码。
- 受控下载：单并发；下载前重新读取作品以刷新短时签名地址；每次跳转重做官方媒体域校验；支持严格 Range 续传、50 GiB 上限、流式 SHA-256、`fsync` 与 Windows 原子 no-replace 提交；同名文件会安全编号，绝不覆盖既有下载。
- 本地元数据：可选的 `<媒体文件名>.json` 只写作品字段、文件名与 SHA-256，不写密码、令牌、签名媒体 URL 或绝对下载目录。
- 保守失败：API 401 与登录认证失败会停止并提示，普通作品/媒体 403 仅失败该项并继续同批任务；429 遵循 `Retry-After`/`X-RateLimit-Reset`，无信号默认等待 10 分钟；5xx 有界退避；不自动切换旧接口。
- 离线回归与 Windows CI：测试发现前同时阻断原生 WinHTTP 和常用 Python 网络入口，自动测试不接触真实账号。

## 便携版使用

便携目录应包含 `App/`、`Runtime/`、启动脚本，以及本机运行后创建的 `Data/` 和 `Downloads/`。

- `启动Sankaku浏览下载器.bat` / `run.bat`：日常启动。
- `启动_带调试窗口.bat` / `run_debug.bat`：查看启动错误。
- `启动_无控制台黑窗.vbs` / `run_silent.vbs`：隐藏控制台启动。
- `运行自动化测试.bat` / `run_tests.bat`：离线测试。
- `verify_portable.bat`：验证包内 Python、依赖来源、Qt WebEngine 和目录可写性。

同一便携目录启动第二个实例时会显示提示并退出。不要删除正在运行实例的 `Data/.app.lock`，也不要让多个用户同时从同一个网络共享目录运行程序。

首次运行：

1. 在“账号与设置”选择下载目录。
2. 如需账号内容，在同页输入账号密码并点击“验证并登录”；勾选后仅保存 DPAPI 加密文件。
3. 在“发现与搜索”输入标签，选择结果加入任务篮；也可从受限站内页收集当前可见作品链接。
4. 在“下载任务”中选择单项或顺序下载全部待处理任务。

默认下载值是相对于当前便携根目录的 `Downloads`，所以整目录搬移后会跟随新位置。用户主动选择的外部目录保存为绝对路径，不会在换盘或换机后自动猜测新位置；搬移后请先检查设置。`Data/.credentials` 受 DPAPI CurrentUser 保护，换 Windows 用户或换机器后需要重新登录。

## 源码开发

项目使用 Python 3.13、PySide6 6.11.2 与 Windows 原生 WinHTTP/Schannel。应用传输不携带 requests、urllib3、PySocks、Python `_ssl` 或 OpenSSL DLL；代理只支持一个不带凭据的显式 HTTP 代理（可为 HTTPS 目标建立 CONNECT），不支持 SOCKS 或 HTTPS-to-proxy。普通开发环境：

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r App\requirements.lock.txt
.\.venv\Scripts\python.exe App\run_tests.py
.\.venv\Scripts\python.exe App\main.py
```

便携 Runtime 不进入 Git。正式发布只能使用来源、版本、架构、哈希和许可证均有记录的 Python 3.13.15 x64 embeddable/PySide6 6.11.2 Runtime；不能仅因另一个项目能够启动就直接复制其 Runtime。必须重新执行依赖检查、离线测试和只读发布门禁。绝不能从其他项目复制 `Data/`、浏览器 Profile、设置、Cookie、缓存、日志或下载内容。

完整 staging、Runtime 布局、只读 `--release` 门禁、SHA-256 清单与搬移烟测步骤见 [PORTABLE_BUILD.md](PORTABLE_BUILD.md)。普通用户运行 `verify_portable.bat` 会检查目录可写性；发布者应改用：

```bat
verify_portable.bat --release
```

## 目录结构

```text
SankakuSyncer_Portable/
├─ App/                 源码、测试、自检
├─ Data/                本机设置、DPAPI 凭据、任务篮（不提交）
├─ Downloads/           默认下载目录（不提交）
├─ Runtime/             便携 Python/Qt（不提交）
├─ run*.bat / *.vbs
├─ README.md
├─ CHANGELOG.md
├─ SECURITY.md
├─ PORTABLE_BUILD.md
└─ THIRD_PARTY_NOTICES.md
```

## 设计边界

- 当前站点数据适配器基于公开可观察的站点行为，未获得稳定性保证；接口变化时会失败关闭。
- 搜索、元数据和下载均由用户明确操作触发；没有后台监视、定时抓取或无限分页。
- `file_url` 可能过期、为空或受账号等级限制；程序不会用缩略图冒充原图，也不会拼接或猜测 CDN 地址。
- 下载文件的存在不授予复制、转载、训练、商业使用或再分发权利。
- 源码采用 MIT License；第三方 Runtime 组件分别受其自身许可证约束，分发者必须随最终包提供完整许可/notices、版本与哈希记录和 SBOM。摘要见 [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)。

更多威胁模型和报告方式见 [SECURITY.md](SECURITY.md)。
