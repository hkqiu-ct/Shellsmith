# BYOS 包外密钥功能完整实现计划

## Context

**问题根源：** DEXB v6 格式的全部密钥材料（IKM、包裹密钥的两个输入：证书指纹 + build_id）均存放在 APK 文件头部明文区域。任何人拿到 APK 文件即可离线还原 IKM 并解密业务代码。项目自身 `rea-resilience.md`（2026-10-19）实测确认：11,613 个 PVM2 保护方法和 27 个 SO 可被公开材料 100% 还原，3 次独立构建规范化指令摘要完全一致，REA 没有被防住。

**目标：** 引入双模式架构：
- **模式一（默认，本地离线）：** 维持现有 DEXB v6 逻辑，现有用户零影响
- **模式二（BYOS 服务端）：** 用户自带服务器（BYOS = Bring Your Own Server），APK 头部只存 `token_id + server_url`，真正的 IKM 由服务端在运行时下发，App 启动时通过 Play Integrity 鉴权后才能拿到密钥

**已确认的关键决策：**
- 运行时鉴权方案：Play Integrity（确认，排除嵌入 api_key 方案，后者对静态分析者无效）
- Shellsmith 官方不运营共享托管服务，只定义协议，用户自带服务器
- Android 4.4 工控兼容线明确不支持 BYOS（无 GMS）
- 默认模式永远不受影响

---

## 实现范围与文件清单

### 阶段一：DEXB v7 格式与 CLI 打包端

**1. `crates/shield-core/src/dex_packer/packer.rs`**

目标状态：
- 版本号常量：`DEXB_VERSION_OFFLINE: u32 = 6`，`DEXB_VERSION_BYOS: u32 = 7`
- `pack()` 方法：与现在完全一致（v6 格式），不得改变任何现有行为
- `pack_byos(output_path, ikm, signature, token_id, server_url)` 方法：写 v7 格式头部
- v7 头部布局（字节序均为 LE）：
  ```
  magic(4B "DEXB") | version(4B = 7) | dex_count(4B) | flags(4B)
  | sig_len(1B) | signature(sig_len B)
  | build_id(16B)
  | token_id_len(2B u16) | token_id(N B)
  | server_url_len(2B u16) | server_url(M B)
  | payload_nonce(12B)
  | ciphertext
  ```
  注意：v7 无 `wrap_nonce` 和 `wrapped_ikm` 字段，APK 内不包含任何可还原 IKM 的材料
- 两个方法共用 `build_payload()` 辅助（压缩 + 加密逻辑不重复）
- 原有测试 `parse_bin()` 和所有 `#[test]` 保持通过，新增 v7 格式的 round-trip 测试
- `离线仅凭包内头部即可还原_ikm_与载荷_这是已知边界()` 测试继续通过（v6 行为不变）；新增对称测试：v7 包无法离线还原

**2. `crates/shield-core/src/dex_packer/mod.rs`**

- 现有 `pack_dex_files_with_layers()` 走 v6，不变
- 新增 `pack_dex_files_byos(input_dir, output_bin, ikm, signature, token_id, server_url, compression_layers)` 函数，内部调用 `packer::DexPacker::pack_byos()`

**3. `crates/shield-core/src/remote_key.rs`**

CLI 侧（加固时上传 IKM 到 BYOS 服务端）：

```rust
pub fn register_ikm(endpoint: &str, ikm: &[u8], api_key: &str) -> Result<String>
```

- POST `{endpoint}/v1/keys/register`
- 请求体：`{"ikm": "<base64>", "api_key": "<api_key>"}`（api_key 用于加固端身份验证，不嵌入 APK）
- 返回服务端分配的 `token_id`
- 使用 `ureq` crate（纯 Rust、同步、无 async 依赖）
- base64 编码使用标准库或已有依赖，不手写

**4. `crates/shield-core/Cargo.toml`**

- 新增 `ureq = { version = "2", features = ["tls"] }`（CLI 侧 HTTP）
- 新增 `base64 = "0.22"` 或使用已有的 `sha2` 依赖提供的 base64（确认后选择）

**5. `crates/shield-core/src/protect_api.rs`**

`ProtectOptions` 结构体（当前 `protect_api.rs:59`）新增两个字段：

```rust
/// BYOS 模式：服务端 API 基础地址。None 时走默认 v6 离线路径。
pub byos_endpoint: Option<String>,
/// BYOS 模式：加固端认证凭据，用于上传 IKM 时向服务端鉴权。不写入 APK。
pub byos_api_key: Option<String>,
```

- 两个字段均为 `None` 时：走现有 v6 路径（所有现有代码路径不受影响）
- 两个字段均有值时：调用 `remote_key::register_ikm()` 上传 IKM，走 v7 打包路径
- 任一字段为 `Some` 而另一个为 `None`：在 `protect_apk()` 入口处提前报错，提示用户必须同时配置两个字段

**6. `crates/shield-core/src/lib.rs`**

- 新增 `mod remote_key;` 并 `pub use remote_key::register_ikm;`（或仅模块内可见，根据是否需要对外暴露决定）

---

### 阶段二：Stub 侧运行时密钥拉取

**7. `shield-stub/build.gradle.kts`**

dependencies 块新增：
```kotlin
implementation("com.google.android.play:integrity:1.4.0")
```

**8. `shield-stub/src/main/java/dev/mocika/shield/loader/Ld.java`**

新增方法（不修改任何现有方法）：

```java
static byte[] fetchRemoteIkm(Context ctx, String serverUrl, String tokenId, String certFingerprint)
```

完整流程：
1. `IntegrityManagerFactory.create(ctx)` 获取 `IntegrityManager`
2. 生成 UUID v4 作为 `nonce`（防重放，绑定到此次请求）
3. `integrityManager.requestIntegrityToken(IntegrityTokenRequest.newBuilder().setNonce(nonce).build())` — 异步，需要在主线程外调用，内部用 `Task.await()` 或 `CountDownLatch` 同步等待
4. 取得 `integrityToken` 后，用 `HttpURLConnection` POST 到 `{serverUrl}/v1/keys/fetch`：
   ```json
   {
     "token_id": "<tokenId>",
     "integrity_token": "<integrityToken>",
     "nonce": "<nonce>",
     "cert_fingerprint": "<certFingerprint>",
     "timestamp": <unix_seconds>
   }
   ```
5. 解析响应 JSON，取出 `ikm` 字段（base64 解码）返回 `byte[]`
6. 任何失败（网络错误、鉴权失败、服务端返回非 200）：抛出 `SecurityException`，不降级到包内材料

注意：Play Integrity API 要求 Google Play Services，在 `catch(Exception)` 中需要区分"GMS 不可用"（抛 `SecurityException`）vs "临时网络错误"（可以有限重试或也抛 `SecurityException`，保持简单）

**9. `shield-stub/src/main/rust/src/lib.rs`**

在 `f2`（绑定到 `STUB_METHOD_EXTRACT_DECRYPT`，当前 `lib.rs:80`）中，DEXB 版本检测逻辑：

```
读取头部 version 字段（偏移 4，4字节 LE）
  version == 6 → 现有 v6 路径（完全不变）
  version == 7 → v7 路径：
    从头部解析 token_id、server_url
    回调 Java: Ld.fetchRemoteIkm(ctx, server_url, token_id, cert_fingerprint) -> byte[]
    拿到 IKM 后走与 v6 完全相同的 HKDF 派生 + ChaCha20-Poly1305 解密
  其他版本 → 返回错误
```

v7 头部解析偏移：
```
[0..4]   magic
[4..8]   version = 7
[8..12]  dex_count
[12..16] flags
[16]     sig_len
[17..17+sig_len]  signature
[17+sig_len..17+sig_len+16]  build_id
[17+sig_len+16..+2]  token_id_len (u16 LE)
[...+token_id_len]   token_id
[...+2]              server_url_len (u16 LE)
[...+server_url_len] server_url
[...+12]             payload_nonce
[...]                ciphertext
```

新增 JNI 方法注册：在 `JNI_OnLoad` 的 RegisterNatives 数组中加入 `Ld.fetchRemoteIkm` 对应的 native 方法（如果回调需要 native 桥接），或直接在 Rust 中通过 `env.call_static_method` 调用 Java 静态方法（更简单，无需新注册项）

**10. `shield-stub/src/main/rust/src/crypto.rs`（Stub 侧）**

确认现有 `derive_key()` 接口签名不变——v7 的 IKM 来源不同但派生逻辑完全复用，无需修改。

---

### 阶段三：BYOS 服务端参考文档

**11. `docs/design/byos-key-server.md`（新建）**

内容：
- BYOS 定位声明：Shellsmith 只定义协议，不运营服务器；用户自建自运维
- API 契约：
  - `POST /v1/keys/register`：加固工具调用，上传 IKM，返回 `token_id`
  - `POST /v1/keys/fetch`：App 运行时调用，提交 Play Integrity token，返回 IKM
- 请求/响应 JSON schema（含必填字段和类型）
- Play Integrity token 服务端验证流程（调用 Google Integrity Verdicts API，检查 `appRecognitionVerdict = PLAY_RECOGNIZED` 等字段）
- 防重放设计：`nonce`（UUID v4，服务端记录已用 nonce）+ `timestamp`（允许 ±5 分钟偏差）
- TLS 要求（仅接受 HTTPS，证书钉选建议）
- 密钥存储建议：数据库侧 IKM 加密存储（不以明文落盘）
- 速率限制、吊销、备份建议
- 不支持 BYOS 的设备范围：Android 4.4 工控线、无 GMS 设备（如 HMS 华为）

---

### 阶段四：文档更新

**12. `docs/design/internals.md`**

在现有 DEXB v6 格式表后新增 v7 格式定义表，标注与 v6 的差异（无 wrap_nonce/wrapped_ikm，改为 token_id/server_url）。

**13. `docs/design/android-code-protection-upgrade.md`**

更新 2026-10-14 决策记录：原"维护者不提供或运维授权服务器"范围限定为"默认离线模式不依赖维护者服务器"；BYOS 模式下用户自带服务器，Shellsmith 只定义协议。

---

## 不在本轮范围内

- Shellsmith 官方托管共享密钥服务（需独立商业/法律决策，后续单独立项）
- iOS 侧对应实现
- Android 4.4 工控兼容线的 BYOS 支持（该线路明确排除，文档注明）
- GUI 侧的 BYOS 配置界面（本轮只做 CLI，GUI 作为后续迭代）
- 密钥轮换/吊销的完整管理界面（文档描述协议，实现由用户自己在服务端完成）

---

## 验证方案

### 单元测试（不需要真实服务端）

`crates/shield-core/src/dex_packer/packer.rs` 测试块：
- `v7_pack_byos_no_wrapped_ikm_in_header()`：v7 产物头部不包含任何可还原 IKM 的材料，即 `wrapped_ikm` 字段不存在，头部字节中不出现明文 IKM
- `v7_pack_byos_roundtrip()`：v7 产物可被正确解析出 `token_id`、`server_url`、`dex_count` 等字段；ciphertext 在已知 IKM（模拟服务端返回）下可正确解密
- 现有全部测试必须继续通过

`crates/shield-core/src/remote_key.rs` 测试：
- `register_ikm_posts_correct_fields()`：用 mockito 或 wiremock 起一个 mock HTTP server，验证请求 body 包含 base64 编码的 ikm 和 api_key 字段，返回 token_id

### 集成测试

`tests/scripts/check-rea-resilience.py` 现有框架，对 v7 产物执行"仅凭 APK 白盒恢复"检查：
- **预期结果：无法还原**（APK 内无 IKM），这是与 v6 最关键的验收差异
- 具体：`ApkRecoveryCheck` 对 v7 产物应返回"无法还原 IKM"而非 panic 或误报通过

CLI 验证：
```bash
shield protect --byos-endpoint https://your-server.com --byos-api-key YOUR_KEY -i app.apk -o protected.apk
```
验证产物头部：`version = 7`，有 `token_id` 字段，无 `wrapped_ikm` 字段。

### 设备验证（人工）

- 安装 v7 加固包（有服务端）：首次启动触发联网 → Play Integrity 鉴权 → 服务端返回 IKM → App 正常启动
- 安装 v7 加固包（断网）：启动失败，抛 `SecurityException`，logcat 输出固定错误码（如 `S01`），不降级到包内材料
- 安装 v6 加固包（默认）：行为与现在完全一致，无任何变化

---

## 实现顺序建议

1. 完善 `packer.rs`（`pack_byos()` 和 `build_payload()`），跑现有测试确认全部通过
2. 完善 `remote_key.rs`（替换手写 base64，完善 register 接口）
3. 更新 `Cargo.toml`（添加 `ureq`）和 `protect_api.rs`（添加 `byos_endpoint`/`byos_api_key` 字段）
4. 更新 `lib.rs`（导出 `remote_key` 模块）
5. 接入 `protect_apk()` 流程（在现有 DEX 打包步骤处根据 `byos_endpoint` 分支）
6. Stub 侧：`Ld.java` 新增 `fetchRemoteIkm()`，`build.gradle.kts` 添加依赖
7. Stub 侧：`lib.rs` 的 `f2` 新增 v7 分支
8. 写文档：`byos-key-server.md`，更新 `internals.md` 和 `android-code-protection-upgrade.md`
9. 补测试，运行全量测试套件

---

## 关键约束

- **v6 路径必须零改动**：任何现有用户的加固流程不受影响
- **v7 失败不降级**：运行时拉取 IKM 失败必须明确报错，禁止静默降级到包内材料（否则攻击者可以故意打垮服务端来绕过保护）
- **api_key 不进 APK**：`byos_api_key` 只用于加固端上传 IKM 时鉴权，不写入 DEXB 头部
- **Play Integrity 不可降级**：Play Integrity 不可用时（无 GMS），启动直接失败，不切换到更弱的鉴权方案
