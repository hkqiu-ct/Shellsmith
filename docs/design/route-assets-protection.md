# 路由 assets 保护设计

本文描述 `arouter_routes.txt` 与 `therouter_registry.txt` 的加密方案。它是下一主题版本的候选实现，不在 1.10.0 的 CI/发布收口批次中默认启用。

## 1. 当前问题

加固器在 `crates/shield-core/src/protect/dex.rs` 中扫描解密后的 DEX，并把路由类名写入：

```text
assets/arouter_routes.txt
assets/therouter_registry.txt
```

这两个文件由壳自己的 `ARouterCompat` / `TheRouterCompat` 读取，不经过第三方框架直接解析。因此可以在壳内完成解密，不需要 Hook 第三方行为。

当前问题不是“框架读不了”，而是 JADX 等工具在加固 APK 上可以直接读到路由索引，降低自动化分析第一段的成本。它不影响 DEXB v6/v7 的既有密钥边界，也不能宣传为“防静态恢复”。

## 2. 目标与非目标

**目标：**

- 加固产物中不再出现两个明文路由 assets。
- 运行时由壳在 DEX 解密后、路由兼容准备前，内存解密并喂给现有兼容层。
- 保持 ARouter/TheRouter 的页面跳转、服务注入和参数注入语义不变。
- 旧包缺少新格式时保留一个版本的明文读取回退；新包不会同时写出明文。

**非目标：**

- 不把该层计入 DEXB 机密性、抗内存提取或抗语义还原证据。
- 不修改第三方 ARouter/TheRouter 的源码或运行时行为。
- 不引入第二套密钥管理；复用 DEXB 的 IKM 域分离派生。

## 3. 格式建议

新增两个 sidecar：

```text
assets/arouter_routes.rtap
assets/therouter_registry.rtap
```

建议格式：

```text
magic(4) = "RTA1"
version(1) = 1
nonce(12)
ciphertext_len(4, LE)
ciphertext (ChaCha20-Poly1305)
```

密钥：

```text
K_route = HKDF-SHA256(IKM, salt = cert_sha256,
                      info = "mocika-shield/route-assets/v1", 32 bytes)
```

每个文件使用独立随机 nonce。AAD 可以绑定包名、格式版本和文件类型，防止两个 sidecar 互换。

## 4. 运行时流程

```text
StubApp.attachBaseContext
  -> Ld.extractDexFiles / decryptDexBuffers
     -> bin_loader 解析 DEXB
     -> route_assets.initialize(K_route)
  -> TheRouterCompat.prepare
     -> 读取 .rtap -> native 解密 -> 解析 HOLDER/SERVICE/ROUTE/AUTOWIRED
StubApp.onCreate
  -> ARouterCompat.prepareARouterRouteMap
     -> 读取 .rtap -> native 解密 -> 过滤 com.alibaba.android.arouter.routes.
```

壳内新增一个最小 native 入口，只接受 `RTA1` 密文并返回 UTF-8 明文；不接受任意路径、任意密钥或明文回退参数。解密失败时：

- 新包：明确失败，不加载空路由表。
- 旧包：兼容层回退到原明文 assets 读取；一个版本周期后移除。

## 5. 打包流程

1. `process_dex` 完成 ARouter/TheRouter 扫描后，序列化路由文本。
2. 使用 `K_route` 加密，写入 `.rtap`。
3. 不再写 `.txt`；如果扫描为空，删除可能存在的旧 `.txt`。
4. `protection_report` 增加路由条目数、加密文件数、格式版本和是否写出明文，不写具体路由类名。
5. 产物核验阶段断言 APK 中不存在两个 `.txt`，且 `.rtap` 能被运行时格式解析。

## 6. 兼容与版本门禁

- 新增 `runtime_metadata` 字段 `route_assets: 1` 或等价能力标记。
- 打包器与壳的握手检查该字段；不匹配时在加固前拒绝，避免新打包器配旧壳导致路由为空。
- 旧包（没有 `.rtap`）继续读取 `.txt`；新包不生成 `.txt`。
- API 19 兼容路径单独验证一次，因为 `TheRouterCompat.prepare` 在 `attachBaseContext` 内执行。

## 7. 验收

- 单元测试：HKDF 域分离、AAD 绑定、篡改密文拒绝、错误版本拒绝、空路由拒绝。
- E2E：`tests/fixtures/android-smoke-app` 加固后断言 APK 不含 `arouter_routes.txt` / `therouter_registry.txt`，且含 `.rtap`。
- 功能：ARouter/TheRouter 页面跳转、服务注入、参数注入、首次安装、清数据、覆盖升级。
- 兼容：API 19、`extractNativeLibs` 两态、BYOS v7、AAB install-time 模块。
- 分析：用 JADX 直接搜索加固 APK，确认两个明文索引消失；不把该结果当作 DEXB 机密性证据。
- 性能：记录启动耗时和 PSS，与未启用路由保护的同一产物对照。

## 8. 停止条件

- 如果 ARouter/TheRouter 的初始化时序无法在任何受支持路径上保证“先解密、后注册”，停止默认启用，保留显式开关。
- 如果 API 19 兼容路径无法在不改变第三方行为的前提下接入，停止该路径，标准模式单独发布。
- 如果新增 native 入口需要扩大 JNI 面或引入新的密钥管理，重新评审，不为了单个 assets 文件扩大攻击面。
