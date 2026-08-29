# Third-party notices

SankakuSyncer 自有源码使用根目录 `LICENSE` 中的 MIT License。便携发行物中的第三方文件仍受各上游条款约束；本文件是范围说明，不替代 `THIRD_PARTY_LICENSES/` 中的完整文本，也不是法律意见。

## 最终发行范围

版本和实际包含关系以 `App/runtime_artifacts.lock.json`、`RUNTIME_INVENTORY.json` 与 `SBOM.spdx.json` 为准：

| 组件 | 固定版本/来源 | 主要许可或说明 |
| --- | --- | --- |
| CPython Windows x64 embeddable | 3.13.15 | PSF-2.0；完整 CPython LICENSE 和官方 artifact SPDX 随附 |
| PySide6 / Addons / Essentials / shiboken6 | 6.11.2 | LGPL-3.0-only OR GPL-2.0-only OR GPL-3.0-only，或有效商业许可；完整 `pyside-setup` LICENSES 随附 |
| QtBase、QtDeclarative、Qt Image Formats、QtPositioning、QtWebChannel、QtWebEngine | 6.11.2 | 相应 Qt 开源/商业条款；每个 exact source archive 的官方 SHA-256 随附 |
| Chromium（随 Qt WebEngine） | Runtime probe 所报版本 | BSD 风格许可及大量第三方条款；完整官方 attribution 页面集合随附 |
| Microsoft Visual C++ Runtime | 最终 DLL version resource 所报版本 | Microsoft VS 2022 C Runtime redistribution terms 随附 |
| Windows UCRT、WinHTTP、Schannel | 支持的 Windows 系统 | 系统依赖，不作为本项目 Runtime 文件再分发 |

最终网络传输使用 Windows WinHTTP/Schannel。`requests`、`urllib3`、`certifi`、`charset-normalizer`、`idna`、`PySocks`、Python `_ssl`/`_hashlib`、OpenSSL DLL 和 Qt `qopensslbackend` 不属于目标 Runtime；若其中任何文件重新出现，artifact lock、许可材料、SBOM/VEX 与安全评估必须先更新，发布门禁不得把它静默归入 CPython 或 PySide。

CPython 官方 artifact SPDX 描述完整官方 embed 制品所使用的源组件。项目的发布 SBOM不会原样声称所有组件都在 lean Runtime 中，而是根据最终文件证据选择实际保留的 bzip2、Expat、libffi、mpdecimal、SQLite、xz、zlib 等组件。Qt 内嵌的 ICU、libpng、WebP、zstd、Mesa/llvmpipe、BoringSSL 等则依据 exact Qt 6.11.2 attribution 页面和实际 Qt payload 记录。实际 6.11.2 codec probe 显示 H.264/HEVC 不可播放、MP3 与 WebM/VP9/Opus 可播放；因此 FFmpeg、libvpx、opus 和 Chromium attribution 都属于强制材料，而不是可选的总索引附件。

## 随包材料与来源固定

`App/tools/collect_third_party_licenses.py` 收集并验证：

- CPython 3.13.15 完整 LICENSE、官方 Windows embed artifact SPDX，以及从外层 SHA-256/size 已验证的官方 embed ZIP 逐成员导出的哈希清单；
- `pyside-setup` 标签 `v6.11.2` 的完整 `LICENSES/`；
- 每个锁定 PySide/shiboken wheel：先验证外层 wheel URL、size、SHA-256，再从 wheel ZIP 逐成员导出 path/size/SHA-256；最终 `METADATA`、`RECORD`（包括其规范空自哈希项）和所有复制文件必须逐字节匹配 wheel 内部成员，不能信任 Runtime 自报元数据；
- Qt 6.11.2 licensing/SBOM 说明、QtBase/QtDeclarative/Qt Image Formats/QtPositioning/QtWebChannel/QtWebEngine 的 exact source archive 官方 `.sha256`；
- 上述实际模块在 Qt 6.11.2 总索引中链接的完整第三方 attribution 明细，包括 Qt WebEngine/Chromium、Mesa llvmpipe 等；
- Qt WebEngine 的 FFmpeg、libvpx、opus 与 Chromium attribution；发布 codec probe 只要发现 H.264 或 HEVC 能力即失败，且不能用禁用 Chromium sandbox 的诊断结果替代正式发布门禁；
- Microsoft VS 2022 C Runtime 官方许可入口及其原始 OOXML 许可文档；
- OpenSSL 3.0 官方漏洞页面快照，供组件重新出现或历史审计时复核。

`THIRD_PARTY_LICENSES/SOURCES.json` 对每份材料记录相对路径、精确官方 HTTPS URL、字节数和 SHA-256，并固定 `App/runtime_artifacts.lock.json`、`RUNTIME_INVENTORY.json`、`SBOM.spdx.json`、`VEX.openvex.json` 的哈希。artifact lock 另行固定每个外层 ZIP/wheel 所派生成员清单自身的 SHA-256，离线门禁不能用一份自报成员表替换这条信任锚。Qt 文档先检查精确 6.11.2 标记，只接受同源且属于实际模块 section 的 detail 链接，并取总索引和 WebEngine 专用索引的并集；`--check` 完全离线、只读。

这些冻结材料与生成的 inventory/SPDX/VEX 是源码工件。普通 tag/release 只允许对已提交字节运行 `--check`，不得在同一 tag 中重新抓取可变页面；上游刷新应作为独立、可审查的源码变更。应用版本由 `App/version.py` 单点提供。

## Runtime inventory、SPDX 与 VEX

`RUNTIME_INVENTORY.json` 是最终 lean Runtime 的逐文件盘点。每个 payload 文件都有 SHA-1、SHA-256、size 和锁定 artifact provenance；PE 文件尽可能记录 version resource，系统依赖来自重新解析的实际 PE imports。`runtime_subset_manifest.sha256` 与 `runtime_subset_report.json` 也作为最终随附审计文件散列，但它们位于 payload manifest 之外以避免循环哈希。

`SBOM.spdx.json` 是确定性 SPDX 2.3 文档：

- `filesAnalyzed: true` 的 Runtime package 包含每个最终文件及其 SHA-1/SHA-256；
- 精确 CPython/wheel artifact package 带锁定外层 SHA-256；
- 每个 Runtime 文件通过 `GENERATED_FROM` 指向已逐成员验证的 artifact；builder 生成的两份审计文件明确标成 builder output，不伪装成 CPython；
- Qt 模块 package 使用官方 exact 6.11.2 source archive SHA-256 固定 provenance；
- UCRT 仅在实际 imports 出现时列为 Windows 系统依赖，不声称随包再分发。

`VEX.openvex.json` 使用 OpenVEX。目标 Schannel Runtime 的完整逐文件盘点证明 OpenSSL 组件不随附时，上述 CVE 使用 `not_affected` 并给出 `component_not_present` justification；这不是仅凭源码扫描作出的推断。若 Runtime 实际出现 OpenSSL 3.0.21，官方 2026-08-25 修复的 CVE-2026-75803、CVE-2026-54874、CVE-2026-63072、CVE-2026-63074、CVE-2026-63076 会被标为 `under_investigation`；源码未直接出现 EVP_Cipher/CMS/CMP/DTLS 调用只是一项有限证据。任何 `affected` 或 `under_investigation` statement 都阻断发布。

## 分发义务

正式发行还必须：

- 保留收集器生成的完整许可包、inventory、SPDX、VEX，以及 Runtime 中的 builder manifest/report；
- 不删除最终 wheel 实际保留的 `*.dist-info` LICENSE/NOTICE/METADATA/RECORD；如与锁定 wheel 成员不一致，停止发布；
- 若按 LGPL 方式动态分发 Qt，保留接收者依法替换或重新链接相应库所需的权利和材料，不施加冲突的额外技术限制；
- 对发行树与最终 ZIP 分别生成 SHA-256，并通过可信渠道提供清单或签名。

可重复生成和离线门禁见 `PORTABLE_BUILD.md`。
