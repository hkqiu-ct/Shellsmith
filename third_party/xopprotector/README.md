# XopProtector（随本仓库分发）

本目录是 [XopProtector](https://github.com/xopJack/XopProtector) 的**部分源码副本**，用于让
Shellsmith 的构建与发布不再依赖外部仓库检出。

## 为什么放在这里

壳运行时（`libmocikashield.so` 里静态链入的 PVM2 解释器）原先由发布 CI 从 XopProtector 的
固定提交编译，而 PVM2 打包器 `tools/xop-pvm2-packer.jar` 是仓库里的构建产物。两者一旦不同源，
镜像格式版本就会超出运行时上限，产物在用户设备上启动即崩：

```
E protector: PVM2 unsupported version 6
java.lang.RuntimeException: VMP not ready
```

把运行时源码放进本仓库后，**两侧同源**并由仓库内的检查守住：

- 加固前握手：`crates/shield-core/src/protect/pvm2_format.rs` 比对打包器声明的版本与运行时上限；
- 发布期闸门：`scripts/verify_pvm2_packager_version.py` 比对内置打包器与 `native/src/main/cpp/vm/pvm2_format.h`。

## 内容

| 路径 | 说明 |
|---|---|
| `native/src/main/cpp/**` | 壳运行时编译所需的完整源码闭包。`shield-stub/src/main/rust/build.rs` 只编译 5 个 `.cpp`（`common/runtime_state.cpp`、`codeitem/multi_dex_code.cpp`、`crypto/aes.cpp`、`vm/pvm2_format.cpp`、`vm/pvm2_interp.cpp`），本目录包含它们及其全部 `#include` 依赖 |
| `packer/src/main/java/**` | 打包器 Java 源码。随仓库分发的 `tools/xop-pvm2-packer.jar` 由这套源码构建，放在这里以便查证与比对 |
| `LICENSE`、`NOTICE` | 上游 Apache-2.0 许可与 NOTICE，与 `tools/licenses/XopProtector-*.txt` 保持一致 |

未包含上游 Gradle 工程。仓库通过 `make build-pvm2` 使用 JDK 17+ 从全部 Java 源码重建，复用分发 JAR 中由 `dependencies.sha256` 锁定的外部依赖，排除全部自有旧类；`make test-pvm2` 验证源码、类文件、依赖与方法保护链路。

## 来源与改动声明

- 上游仓库：`xopJack/XopProtector`
- 基准提交：`e408b87871ea18e197b189e787c73cc5ae3e2ee6`（2026-09-19）
- 引入本仓库：2026-10-10

**本目录不是上游基准提交的原样副本**，包含相对该提交的修改，主要差异：

- PVM2 镜像格式升到 v7，增加认证的逐方法明文清理策略；方法报告 schema 为 2
- 运行时加入可靠明文清零、引用计数与字节预算；必保方法最后一次调用结束立即清理，普通方法使用有限缓存
- 打包器新增资源、资源 ID、资产与原生库变换子命令（`resource-id-transform`、`res-transform`、
  `assets-transform`、`native-so-transform`）
- 打包器新增 `Pvm2Report`、`Pvm2Safety`、`PlaybackCompatibility`、`AssetCallsiteRewriter`、`ResourceIdRewriter`

按 Apache-2.0 第 4(b) 条要求，上述改动在此声明。上游若有更新的修复，可设置
`MOCIKA_XOP_ROOT` 指向新的 XopProtector 检出以覆盖本目录（例如 `MOCIKA_XOP_ROOT=/path/to/XopProtector`），
但请同时确认内置打包器 JAR 与该检出同源。
