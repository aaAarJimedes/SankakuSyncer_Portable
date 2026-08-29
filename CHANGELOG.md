# 更新记录

本项目遵循语义化版本号。每个版本在通过离线回归、便携自检和私有数据扫描后再提交并同步到 GitHub。

## 0.1.0 - 2026-08-29

- 首个可用版本：原生标签搜索、Safe 默认分级、缩略图网格和受限站内浏览。
- 支持账号令牌登录、Windows DPAPI 可选保存；密码与令牌不进入普通设置、日志或任务文件。
- 提供持久化任务篮、单实例保护、顺序下载、取消、重试和异常退出恢复。
- 下载前刷新作品元数据；官方媒体域逐跳校验；严格 Range/If-Range 续传、大小/签名/MD5 校验和原子 no-replace 提交。
- original/sample/preview 分别命名和校验；派生媒体按实际 MIME 与文件签名决定扩展名，歧义容器失败关闭；同名结果安全编号，不覆盖既有文件。
- 提供相对默认下载目录、可选脱敏 JSON 元数据、代理设置和保守限流/退避。
- 加入离线测试、Windows CI、便携发行门禁、SHA-256 清单生成和第三方组件说明。
- 应用 HTTP 传输改为 Windows WinHTTP/Schannel，移除 requests/urllib3/PySocks、Python OpenSSL 扩展、OpenSSL DLL 与 Qt OpenSSL TLS 插件；强制 TLS 1.2、证书吊销检查、手动跳转和无 Cookie/环境凭据会话。
- 正式启动在导入 Qt WebEngine 前清理继承的调试、禁沙箱、代理和 TLS key-log 环境变量，并强制 Qt Schannel 后端。
