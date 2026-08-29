# Windows x64 便携发行流程

本文定义发布门禁。最终归档必须从干净 staging 产生，不能直接压缩开发工作树或用户运行过的目录。

## 1. 固定 Runtime 来源

基础解释器是官方 **CPython 3.13.15 Windows x64 embeddable**，Qt/PySide6 为 **6.11.2**。所有输入制品必须列在 `App/runtime_artifacts.lock.json`，其中固定规范 HTTPS URL、文件名、字节数、外层 SHA-256，以及由该外层制品派生的成员清单 SHA-256；Python 包版本同时与 `App/requirements.lock.txt` 一致。只允许从这些已锁定制品构建，不能从普通 `venv`、全局 site-packages 或临时网络索引复制文件。

embedded 布局至少包含：

```text
Runtime/
├─ python.exe
├─ pythonw.exe
├─ python313.dll
├─ python313.zip
├─ python313._pth        # 仅相对路径，并启用 import site
└─ Lib/site-packages/
```

先按 lock 精确下载并认证制品，再离线解包成完整 Runtime 来源：

```bat
python -B App\tools\fetch_runtime_artifacts.py --wheelhouse "_runtime_wheelhouse"
python -B App\tools\prepare_runtime_source.py --wheelhouse "_runtime_wheelhouse" --destination "_runtime_source_staging" --clean
```

随后从已审计完整 Runtime 生成精简副本，显式传入来源：

```bat
python -B App\tools\build_runtime_subset.py --source "_runtime_source_staging" --destination "_runtime_subset_staging" --clean
```

下载器使用 no-clobber 发布语义，已有错误制品不会被覆盖；解包器在修改旧目标前重新验证所有 artifact。`--clean` 只接受带精确 builder sentinel 的旧构建目标。构建成功并审核 report 后，精确删除 `_runtime_subset_staging/.sankakusyncer-runtime-subset-builder`，然后：

- **只删除** `.sankakusyncer-runtime-subset-builder`；它是允许清理构建目标的哨兵，禁止进入发行物；
- **必须保留** `runtime_subset_manifest.sha256` 和 `runtime_subset_report.json`；二者是发布门禁重新核对 payload 的依据；
- 不得加入 manifest 未列出的文件，也不得修改 manifest 已列文件；
- report 必须严格使用确定性的 schema 3：顶层 key 集合、各字段类型和 verification 顺序必须精确，`artifact_name` 固定为 `SankakuSyncer_Runtime_Lean`；Python/Qt 版本、file count、bytes 和 PE count 必须吻合，`unresolved_imports` 与 `forbidden_files` 必须为空，所有 verification 的 `returncode` 必须是整数 0（JSON `false` 不接受）。schema 3 不得重新加入时间戳、耗时或构建目标目录名。

正式 Runtime 不得含 `__pycache__`、`.pyc`、`.pyo`、测试缓存、安装器或未锁定 DLL。

## 2. 收集许可、盘点 Runtime、生成 SPDX/VEX

只有最终 lean Runtime 确定且确实要更新上游冻结材料时，才在装有 PowerShell 7 的可信联网构建环境刷新：

```bat
python -B App\tools\collect_third_party_licenses.py --runtime "_runtime_subset_staging"
```

收集器生成：

- `THIRD_PARTY_LICENSES/`：冻结的官方许可证、notices、精确 Qt 6.11.2 source archive checksum、CPython 官方 artifact SPDX 和 embed ZIP 成员哈希清单；
- `THIRD_PARTY_LICENSES/SOURCES.json`：每份材料的 URL、字节数和 SHA-256，以及四份根级审计文档的哈希；
- `RUNTIME_INVENTORY.json`：最终 Runtime 的每个随附文件、SHA-1/SHA-256、大小、PE 版本、实际依赖和锁定 artifact provenance；
- `SBOM.spdx.json`：SPDX 2.3，包含最终 Runtime 文件、精确 wheel/CPython artifact hash、Qt source provenance 和有证据的原生组件；
- `VEX.openvex.json`：有效 OpenVEX。完整 Runtime 盘点证明组件不随附时，可使用 `not_affected` + `component_not_present`；仍在受影响范围且可达性未被充分证明时使用 `under_investigation`，不得仅凭“源码无直接调用”武断写 `not_affected`。

收集器会下载并校验锁定的 CPython embed ZIP 与每个 wheel，逐成员建立 provenance。Runtime 内的 `METADATA`/`RECORD` 不作为信任根：它们和其他 wheel 文件一样，必须逐字节匹配外层 SHA-256/size 已验证的精确 wheel ZIP 成员。除受控的 `python313._pth` 相对路径改写和两份 builder 审计文件外，任何不能对应到锁定 artifact 的 Runtime 文件都会使生成失败。

刷新先在同卷事务 staging 写入并完整验证，成功后才换入正式目录；失败会恢复上一版。生成的 `THIRD_PARTY_LICENSES/`、`RUNTIME_INVENTORY.json`、`SBOM.spdx.json`、`VEX.openvex.json` 和成员清单锚必须与源码一起提交。应用版本统一取自 `App/version.py`。tag/release 工作流禁止重新抓取 Qt、Microsoft 或 OpenSSL 的可变页面，只能复核已提交的冻结字节。

Qt 许可来源固定到 6.11 文档快照和 6.11.2 官方 source archive `.sha256`。收集范围覆盖实际纳入的 QtBase、QtDeclarative、Qt Image Formats、QtPositioning、QtWebChannel、QtWebEngine，以及这些模块索引链接的完整第三方 attribution 明细；不能只保存总索引或只保存 WebEngine 页面。

断网执行只读复核：

```bat
python -B App\tools\collect_third_party_licenses.py --check --runtime "_runtime_subset_staging"
```

`--check` 只依赖包内 Python：它会重新散列整个 Runtime、严格重算 builder manifest/report、由 artifact lock 密码学固定的 wheel/CPython 成员 ownership、inventory、SPDX 和 VEX，并拒绝 missing、extra、hash 变化、符号链接或未登记材料。build host/CI 还须对冻结的官方 JSON Schema 运行完整 Draft 校验：

```bat
python -B App\tools\collect_third_party_licenses.py --check --full-schema-check --runtime "_runtime_subset_staging"
```

`--full-schema-check` 仅用于装有 PowerShell 7 的生成/CI 主机；便携自检使用等价的内置严格结构、ID 引用、checksum 和 package verification code 校验，不修改或放宽生产 `PATH`。

## 3. 组装干净 staging

不要手工挑选或复制发行文件。许可/SBOM 生成并离线复核通过后，使用显式 allowlist 组装器；目标必须尚不存在：

```bat
python -B App\tools\assemble_portable.py --source "." --runtime "_runtime_subset_staging" --destination "..\SankakuSyncer_Portable_Staging"
```

目标目录必须位于源码树之外，且名称应明确包含 `SankakuSyncer` 与 `Portable`/`Staging`/`Release`。组装器要求 Runtime 已去除 builder sentinel，并强制保留 `runtime_subset_manifest.sha256`、`runtime_subset_report.json`；它也要求源码侧已经存在 `THIRD_PARTY_LICENSES/`、`RUNTIME_INVENTORY.json`、`SBOM.spdx.json`、`VEX.openvex.json` 等完整发行集合。它会拒绝已有目标、链接、缓存、私有或清单外内容，以及不符合 `.gitattributes` 的 LF-only BAT/VBS 启动器。

不要带入：

- `Data/`、`Downloads/` 中的内容；
- `.credentials`、`settings.json`、`tasks.json`、Cookie、Profile、媒体和元数据；
- builder sentinel、`__pycache__`、`.pyc`、`.part`、`.log`、临时文件；
- `.env*`、私钥/证书容器（`.key`、`.pem`、`.p12`、`.pfx`、`.kdbx`）和常见凭据 JSON；
- `.git` 等版本库元数据，或含构建机绝对路径的配置。

许可和审计 JSON 按字节校验；`.gitattributes` 已将 `THIRD_PARTY_LICENSES/**`、`SBOM.spdx.json`、`RUNTIME_INVENTORY.json`、`VEX.openvex.json` 和 artifact lock 标为 `-text`，不得让 checkout 自动转换行尾。

## 4. 离线验证

先运行离线测试：

```bat
run_tests.bat
```

再执行只读发布门禁：

```bat
verify_portable.bat --release
Runtime\python.exe -B App\tools\probe_webengine_codecs.py --require-no-patented-video
```

第一项门禁不会创建用户目录、临时 probe、QApplication 或浏览器 Profile。它会检查 Python 3.13.15 x64 embedded 布局、锁定包、Qt WebEngine helper/plugins/resources/locales、整个 Runtime 的 manifest/report/provenance、许可材料、inventory、SPDX、VEX，并扫描私密、生成、绝对路径和链接内容。任一 OpenVEX statement 仍为 `affected` 或 `under_investigation` 时发布失败。

第二项是无网络 codec probe：H.264 或 HEVC 的 `canPlayType` 只要返回非空即失败；MP4 容器本身可能返回 `maybe`，不能据此推断专有视频解码器存在。已验证的 6.11.2 构建对 MP3 与 WebM/VP9/Opus 返回支持，因此许可包和 SBOM 必须保留 FFmpeg、libvpx、opus 及 Chromium 的实际 attribution。codec probe 先清除继承的 Chromium 调试和 `--no-sandbox` 设置；正式发布和启动绝不关闭 Chromium sandbox。受 Windows job 限制而无法启动 sandbox 的本机构建环境不能据此放宽门禁，干净发布 runner 仍须完成 sandbox WebEngine smoke 和 codec probe。

## 5. 清单、归档与搬移烟测

门禁通过后生成并复核发行树清单：

```bat
Runtime\python.exe -B -s App\tools\build_manifest.py --root "."
Runtime\python.exe -B -s App\tools\build_manifest.py --root "." --check
Runtime\python.exe -B -s App\tools\build_deterministic_zip.py --source "." --output "..\SankakuSyncer_Portable-v0.1.0.zip"
```

`SHA256SUMS.txt` 覆盖除私有目录和清单自身外的发行树。确定性 ZIP 工具按规范化 UTF-8 路径排序、写入固定 DOS 时间与权限属性、拒绝链接和树内输出；相同发行树的重复构建必须逐字节一致。最终 ZIP 还需另算 SHA-256，并按发布策略签名。把 ZIP 解压到含空格和非 ASCII 字符的一次性目录，再次运行清单检查和发布门禁，并人工检查启动、搜索、浏览、下载和取消。烟测产生的用户数据不能回灌正式发行目录。
