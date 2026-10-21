# BYOS 本地验收记录

日期：2026-10-20。分支：`feature/byos-remote-key`。基础提交：`0e43d2a`。

本轮完成 GUI/CLI、DEXB v7、专用 Android 运行时、加密配置保存和服务接入协议的本地实现。**真实 HTTPS 服务尚未提供，Play 模式还缺 Play 环境，当前不能视为 BYOS 上线验收通过。** 默认离线模式仍为 v6。

## 已验证

| 检查 | 结果与范围 |
|---|---|
| `cargo test -p shield-core -p shield-cli` | 核心 241 项、诊断集成 4 项通过；CLI 测试在 lib/bin 两个目标各通过 20 项。核心默认忽略 8 项需额外工具或环境的检查 |
| `cargo test -p shield-core v7_java_whitebox -- --ignored` | 单独执行并通过：真实 v7 打包器与 Rust 解密器交叉验证，再用 Java 检查合法、截断、未知版本产物；截断/未知版本没有生成成功报告 |
| v7 密码与缓存检查 | 三种压缩层往返；APK 头部无原始 IKM；缺钥、错误密钥、v6 公开材料、错误证书、篡改头部/密文和所有截断前缀均拒绝；无 PVM2 的缓存路径也要求密钥 |
| 注册与准入检查 | 本地 TCP 模拟验证 POST 字段、Base64、非 200、带 Location 的跳转拒绝、无效 token、凭据脱敏；HTTPS 地址、endpoint/API key/auth 三项完整检查、模式确认和旧协议拒绝通过 |
| CLI 实际调用 | 从环境读取测试凭据，低版本 APK 被 API 29 门槛拒绝；错误不泄露凭据；新增设备授权/Play 资源错配的实际 CLI 拒绝检查，已有目标文件保持原字节 |
| Java 单元测试 | 设备/Play 两种 BYOS 各 54 项、默认离线 51 项通过，包括 nonce 九个字段绑定、固定向量、OAEP 往返与错误密钥/请求/密文/MGF1 参数拒绝 |
| 资源构建 | 设备 BYOS、Play BYOS 与默认离线资源均完成 arm64-v8a、armeabi-v7a、x86、x86_64 构建，Native 16 KB LOAD 对齐检查通过 |
| 依赖隔离 | BYOS SDK 经统一裁剪/改名后未留下原 Google/AndroidX 公共类；构建脚本将残留类视为失败。默认及设备授权资源没有 Play Integrity 服务连接字符串；只有 Play 资源包含该连接路径 |
| 编译与静态检查 | CLI 构建、GUI 140 项测试（另有 3 项忽略）、前端 31 项测试、TS/ESLint、core/CLI/GUI 全目标 Clippy（warnings 作为错误）、格式和 diff 检查通过 |
| 仓库样本设备回归 | 独立测试包在 Android 15 / ARM64 的授权设备安装成功；首次启动和强停后的再次启动均成功，无致命异常。逐方法报告选中 11 项，转换并验证 10 项。测试包已卸载 |
| 用户授权 APK 回归 | 使用用户提供的真实 APK 在本次模式拆分后重新执行默认 v6 离线加固，8 份 DEX 打包、资源保留、Runtime 注入、重打包与对齐成功。此项未开启 PVM2，不代替该 APK 的方法覆盖或业务真机验收；生成的是未签名回归产物 |
| 默认格式恢复回归 | Java 白盒检查从该 v6 回归 APK 恢复全部 8 份 DEX，报告哈希匹配，证明既有公开材料恢复路径仍然存在；这不是 BYOS 抗还原验收 |

## 桌面配置与分发补齐

独立测试包：`target/release/bundle/macos/Shellsmith BYOS Test.app`。已对完整 `.app` 补齐 adhoc 本地签名并通过严格校验；未做 Developer ID 公证、未发布、未签发版本 tag，正式版本配置未替换。测试标识为 `dev.mocika.shellsmith-byos-test`，仅含无效占位服务配置，不能直接请求生产密钥。

已实际操作 macOS `.app`：载入授权 APK → 新增设备授权配置 → 保存 → 编辑时 API key 不回显 → 改选 Play 显示条件说明 → 留空旧凭据保存被拒绝 → 取消编辑 → 低于 API 29 的 APK 显示 BYOS 阻断且不能开始 → 恢复默认后回到离线并可开始。保存时没有访问占位服务、上传 APK 或执行加固输出覆盖。

后端检查确认该测试配置在 `shield.db` 内为整行 `enc:v1` 密文，地址与占位 API key 未明文落盘；独立密钥 32 字节/0600，应用目录 0700。单元测试另覆盖空白凭据保留、地址/模式变更必须重填凭据、本地密钥缺失或损坏拒绝覆盖。

界面验证发现并修正了 `build.rs` 覆盖 CLI `TAURI_CONFIG` 的问题：现在只替换图标并保留独立应用标识。重新构建/启动后，已核实测试数据库独立且没有正式证书记录。复现构建：

```bash
cd apps/shield-gui
cargo tauri build --bundles app --config '{"productName":"Shellsmith BYOS Test","identifier":"dev.mocika.shellsmith-byos-test","bundle":{"createUpdaterArtifacts":false}}'
cd ../..
codesign --force --deep --sign - 'target/release/bundle/macos/Shellsmith BYOS Test.app'
codesign --verify --deep --strict 'target/release/bundle/macos/Shellsmith BYOS Test.app'
```

CLI/GUI 的 macOS、Linux、Windows 发布脚本及 CI 资源清单已包含设备/Play 专用 ZIP；Native 中间目录共用，Make 构建顺序串行。实际 `.app` 随包资源已执行以下检查，三套 ZIP 的模式、协议、Google 依赖隔离及四 ABI 均通过：

```bash
python3 tests/scripts/check-byos-resources.py 'target/release/bundle/macos/Shellsmith BYOS Test.app/Contents/Resources/resources'
cargo test -p mocika-shield byos::tests
cargo clippy -p shield-core -p shield-cli -p mocika-shield --all-targets -- -D warnings
```

本次已验证 macOS 构建与交互；Windows/Linux 发布脚本仅完成代码核查，仍需对应 CI 原生构建验证。未使用没有部署的真实 HTTPS 服务或 Play 环境，不能把桌面配置通过等同于在线授权通过。

## 连接检查补充

新增“测试连接”：支持未保存草稿和已保存配置；只读调用 `/v1/keys/check`，显示固定错误分类、耗时、HTTP 状态，以及 HTTPS、凭据授权和模式/协议验证状态。编辑参数或切换配置后清除结果。测试不保存草稿、不生成 IKM、不注册 token；取用已存凭据复用保存路径的地址/模式变更保护。

自动测试已覆盖 18 种响应与失败路径：成功、401/403、404/405、重定向、限流、5xx、非预期状态、HTML 假成功、错误请求 ID、错误服务标识、错误模式、旧协议、授权拒绝、超长响应、重复 JSON 字段与超时。全部结果不含凭据或响应原文。

额外实际运行 `connection_probe_real_tls`：OpenSSL 临时生成 CA 和服务证书，Rustls 本地服务完成 HTTPS 请求/响应；测试客户端显式信任临时 CA 时成功，默认客户端拒绝不可信 CA，可信 CA 但主机名错误也拒绝。失败握手未收到 HTTP 凭据。信任配置仅存在测试进程中，没有导入系统证书、关闭 TLS 校验或修改生产信任策略。

```bash
cargo test -p shield-core connection_probe
cargo test -p shield-core connection_probe_real_tls -- --ignored
cargo test -p mocika-shield byos::tests
```

真实 TLS 测试默认忽略以免将 OpenSSL 变成普通单元测试的必需条件，已加入 Linux CI 显式执行步骤；本地已单独执行通过。测试证据为 `connection-probe-tests.log`、`connection-full-tests.log`、`connection-clippy.log`。

桌面实际打开后已确认新增/编辑表单显示“测试连接”，未填写地址和凭据时按钮禁用。随后 Mac 锁屏，尚未完成该按钮的实际点击及结果显示验证；这项不计为通过。本地临时 UI 测试服务已停止。

本次测试包为 `target/release/bundle/macos/Shellsmith BYOS Connection Test.app`，应用标识 `dev.mocika.shellsmith-byos-connection-test`，数据目录独立于正式版和上一轮测试版。服务端新增接口的请求、响应、拒绝规则见 [接入文档](../design/byos-key-server.md#桌面连接测试只读)。成功检查不能代替最终 APK 的注册、取钥与启动联调。

## 设备授权与响应加密补充

授权设备 Android 15 / ARM64 上运行 `ByosDeviceContractTest`，使用真实 Android Keystore，测试连接由测试 APK 内的 HTTPS 模拟响应替代。覆盖私钥不可导出、并发首次生成与同身份密钥复用、未批准拒绝、批准后正确 IKM、重复 nonce 拒绝、新请求可继续、响应模式/nonce/明文字段/密文错误和重定向拒绝、撤销后拒绝。全部断言通过，测试 APK 已卸载。

此项不是正式 HTTPS、实际后台管理服务、R8 发布 APK 完整启动或多进程业务验收。首次运行发现仓库默认 AndroidJUnitRunner 未实际包含，已改为平台 Instrumentation 加现有 JUnit，未引入测试依赖。可复现命令：

```bash
MOCIKA_BYOS_RUNTIME=1 ./shield-stub/gradlew -p shield-stub assembleDebugAndroidTest
adb -s YOUR_AUTHORIZED_DEVICE install -t shield-stub/build-byos/outputs/apk/androidTest/debug/shield-stub-debug-androidTest.apk
adb -s YOUR_AUTHORIZED_DEVICE shell am instrument -w dev.mocika.shield.stub.test/dev.mocika.shield.loader.ByosDeviceContractTest
```

对应证据为 `device-contract.log`、`device-java-tests.log`、`play-java-tests.log`、`device-resource-build.log`、`play-resource-build.log`、`modes-rust-tests.log`、`modes-clippy.log`。设备模式的完整生产授权效果仍须按服务协议验证，不能将测试内的批准状态当成已经交付了生产服务。

运行环境：macOS、JDK 17、Android SDK 35 编译平台、NDK 29.0.14206865、Play Integrity 1.4.0。本轮没有重新执行 API 19、Windows 或 Linux 的全套构建/设备验收。

本地证据目录：`target/byos-20261020/`。该目录被 Git 忽略，包含样本标识、APK 和恢复代码，不应整体公开上传。日志包含构建、Rust/Java 测试、CLI 拒绝结果及设备回归记录。

## 独立产物密钥与客户秘密接入补充

BYOS 不再使用本机项目种子派生产物 IKM，每次构建由密码学随机源独立生成 32 字节材料。项目身份继续复用；报告只标记独立来源，不写 IKM 或项目派生盐。默认离线派生和旧产物协议保持兼容。

已执行 `cargo test -p shield-core`：242 项单元测试和 4 项诊断集成测试通过，8 项需外部条件的测试保持忽略。新增检查用真实项目导出/导入证明：同一备份仍保持项目身份，但 BYOS 每次使用不同材料；离线 HKDF 契约保持。现有 v7 回归改为使用真实构建材料生成路径，检查项目派生密钥无法解密、正确 BYOS 密钥可通过三种压缩层与发布运行时解析器往返。

`cargo clippy -p shield-core -p shield-cli -p mocika-shield --all-targets -- -D warnings` 通过。证据为 `independent-keys-tests.log`、`independent-keys-clippy.log`。

已重新构建 `target/release/bundle/macos/Shellsmith BYOS Connection Test.app`，完成本地临时签名、严格签名校验与随包三套运行资源检查；构建证据为 `independent-keys-app-build.log`。本轮没有新增界面交互测试，也没有发布正式版本。

客户 KMS/HSM、数据库主密钥、账号 Token、签名和许可证的接入角色、稳定 IKM 与主密钥轮换约束已写入服务协议。这是服务端接入文档，不是已实现所有厂商适配器或任意手机算法协商；尚无客户真实后端，未做这部分联通验收。构建机内存与授权手机进程仍能持有当次 IKM。

## 自有随机主密钥与 KMS/HSM 接入补充

用户确认接入范围为客户自有随机密钥、KMS/HSM。服务端配置示例、封存/解封/就绪检查的能力边界、上下文绑定和历史密钥轮换已补齐；桌面不新增服务器主秘密输入项。实际厂商适配器由客户后端实现，尚无真实密钥服务环境，不计为联通通过。

连接检查复用原接口：HTTP 503 且正文严格为 `{"error":"KEY_BACKEND_UNAVAILABLE"}` 时显示密钥后端未就绪；重复字段、额外字段或未知错误码归为普通服务错误，不泄漏原文。成功五字段及手机协议保持不变，桌面测试不是独立的 KMS/HSM 可用性证明。

本轮执行 `cargo test -p shield-core connection_probe`，原有 18 种路径及新增 5 种后端错误分类用例通过；另行执行真实 TLS 测试，可信测试证书可连接、不可信 CA/错主机名拒绝。证据为 `key-backend-probe-tests.log`。核心、CLI、GUI 的 all-targets Clippy、前端类型检查与 lint 通过；Clippy 证据为 `key-backend-clippy.log`。

已重建 `target/release/bundle/macos/Shellsmith BYOS Connection Test.app` 并通过本地临时签名校验及三套随包运行资源检查，构建日志为 `key-backend-app-build.log`。本轮未新增桌面实际点击或真实厂商 KMS/HSM 验证，未发布正式版本。

## 外部环境就绪后必须补齐

1. 用户部署 HTTPS 服务，配置应用、最终签名证书、所选授权方式、构建 API key、数据库加密和原子防重放存储；仅 Play 模式增加 versionCode 与 Google 身份。
2. 设备模式通过客户服务批准，Play 模式经测试轨道安装，完成真实 HTTPS 注册 → 对应证明 → 服务端授权 → OAEP 加密响应 → JNI 解密 → 业务启动；首启与缓存启动都要验证。
3. 验证断网、设备未批准/撤销、TLS 错误、超时、吊销、错误身份策略、并发重放和篡改响应均不能加载业务；Play 模式另验版本、无 GMS 和 Google 拒绝。恢复网络后可重新发起请求。
4. 对真实 v7 产物运行 REA 与白盒检查，记录分析范围。`external_key_required` 只说明当前公开材料恢复路径缺少外部秘密，不能代替服务器安全或动态抗提取验收。
5. 测量冷启动、缓存启动、多进程、ANR；仅 Play 模式统计 Google 配额。两次本地离线启动只属于功能回归，不属于性能统计验收。

本轮 BYOS 输入门槛是 Android 10+；默认离线兼容范围不变。服务实现和完整验收输入见 [HTTPS 密钥服务接入协议](../design/byos-key-server.md)。


## 2026-10-21：按授权方式拆分最低系统要求

设备授权最低输入版本改为 `minSdkVersion >= 26`（Android 8.0）；Play 模式保留 `>= 29`（Android 10），原因是当前同步启动路径使用 API 29 的服务绑定 Executor，并非 Google SDK 本身要求 API 29。此前记录的统一 API 29 门槛已被本节取代。

同时修复设备授权的早期启动问题：API 26～30 的 AndroidKeyStore 构造依赖全局 Application，但壳在 `attachBaseContext` 取钥时框架尚未填入。取钥期间临时提供已经 attach 的壳 Application；成功、拒绝、超时和异常结束均恢复原状态，不覆盖已有 Application。API 31 以上不进入该兼容分支。旧系统框架字段不可访问时拒绝启动，不改用软件设备密钥。依据可查 [Android 8.0 KeyStore 实现](https://android.googlesource.com/platform/frameworks/base/+/android-8.0.0_r1/keystore/java/android/security/KeyStore.java)。

本次检查结果：

- Android 8.0 / API 26、Android 9 / API 28 ARM64 模拟器：均在真正的 `Application.attachBaseContext` 主线程执行协议测试，首次安装和再次启动各通过一次。覆盖并发生成同一设备密钥、私钥不可导出、批准前拒绝、批准后取钥、重放拒绝、错误身份/密文/明文响应、跳转、8 秒超时、撤销，以及启动上下文恢复。
- 核心最低版本矩阵：19、23、25、26、27、28、29、30、35 和无效值，分别验证设备/Play 模式；拒绝结果不修改 Manifest。旧设备授权 API 29 资源必须重建，不能用旧运行时冒充 API 26 支持。
- BYOS 核心回归 25 通过、1 项跨语言白盒测试按原配置忽略；设备和 Play Java 单测通过；GUI 前端 31 项通过，类型检查、lint、Rust clippy 通过。
- 三套四 ABI 运行时均重新构建；分发 ZIP 检查通过，设备资源声明 API 26，Play 声明 API 29，设备资源没有 Google SDK。
- 已提供样本的原始 Manifest 确认为 `minSdkVersion=26`，符合新的设备授权版本要求。未修改样本的系统声明，未连接客户的真实密钥服务，因此不把该结果描述为样本 BYOS 整包联调通过。
- 已重新构建 `target/release/bundle/macos/Shellsmith BYOS Connection Test.app`；包内三套资源检查和本机 ad hoc 签名严格验证通过，尚未公证或发布。

启动回归可复用现有 Gradle 与 ADB，无需真实服务凭据：

```bash
MOCIKA_BYOS_RUNTIME=1 MOCIKA_BYOS_PLAY_INTEGRITY=0 ./shield-stub/gradlew -p shield-stub testReleaseUnitTest assembleDebugAndroidTest
adb -s YOUR_TEST_DEVICE install -r shield-stub/build-byos/outputs/apk/androidTest/debug/shield-stub-debug-androidTest.apk
adb -s YOUR_TEST_DEVICE shell am instrument -w dev.mocika.shield.stub.test/dev.mocika.shield.loader.ByosDeviceContractTest
```

测试 APK 内拦截 HTTPS 连接，使用真实系统 Keystore；它验证启动期协议与兼容逻辑，不验证真实 TLS 服务、Google 签发证明或所有厂商 ROM。运行记录位于忽略目录 `target/byos-20261020/api26-*` 和 `api28-startup-cached.txt`。

## 2026-10-21：最终资源 JNI 注册与真实服务拒绝排查

用户产物在 Android 15 ARM64 真机启动时报 `JNI_ERR returned from JNI_OnLoad`。问题发生在网络取钥之前：BYOS 使用独立 R8 编译，缺少 AGP 默认 native 保留规则；`Ld.s(Context, byte[])` 和 `Ld.t(Context, byte[])` 被改名，Native 仍按 `s`、`t` 注册。此前 Java 协议测试使用未混淆类，没有覆盖最终 DEX 与 SO 的注册关系。先前“启动期协议通过”不能代表分发运行时已完成整包启动验收。

修复包括固定这两个 JNI 名称，继续保留完整回调类；独立 R8 构建结束后检查固定 JNI 入口，发现缺失或重命名即拒绝打包。增加最终资源真机检查：

```bash
ANDROID_HOME=/path/to/android-sdk python3 tests/scripts/check-runtime-jni.py \
  shield-stub/build/outputs/resources/resources-byos.zip --serial YOUR_TEST_DEVICE
ANDROID_HOME=/path/to/android-sdk python3 tests/scripts/check-runtime-jni.py \
  shield-stub/build/outputs/resources/resources-byos-play.zip --serial YOUR_TEST_DEVICE
```

该检查使用分发 ZIP 内原样 DEX/SO，自动寻找 JNI 回调类并触发实际注册；使用独立测试包，不访问密钥服务。旧设备授权资源稳定复现 JNI_ERR，修复后的设备与 Play 资源均通过 ARM64 真机检查。

继续用用户产物回归：保持包名、原签名、BYOS 令牌和加密载荷不变，仅修复壳运行时；同签名覆盖安装后已越过 JNI 注册，真实 `/v1/keys/fetch` 返回 HTTP 403。为避免所有错误都被压成 K01，手机端现在保留脱敏 HTTP 状态和 DNS、TLS、超时、密钥及响应分类，不打印服务原文或秘密。真实服务器拒绝原因须由服务端批准记录及日志确认，不能据此宣称整个业务启动成功。拒绝不会回退到离线密钥。

本地证据在 `target/byos-crash-20261021/`，包含原始崩溃、旧/新资源探针、真实 HTTP 403 日志和签名修复包；目录不提交、不整体公开上传。

## 2026-10-21：真实设备授权服务与样本启动通过

服务器应用清单及产物记录确认，失败 APK 的 token 仍绑定文档示例包名和示例证书。新建正确应用策略不会改变旧构建 API key 的归属，已有 token 也保留注册时的策略快照。包名/证书校验先于设备登记，因此查询正确应用的待批准列表为空。现有连接检查只验证凭据、授权方式与协议，不能证明 APK 身份与服务端策略相符。

使用用户为正确应用创建的新凭据，按现有加密存储格式保存独立命名配置，再从原始 APK 重新加固；保留严格环境策略、严格保护、高 AI 抵抗和原业务前缀。PVM2 转换方法数仍为 10,379，与此前产物一致。签名 v2/v3 和 16 KB ZIP 对齐验证通过，同签名覆盖安装，未卸载或清数据。

新产物首次请求后，服务器出现与启动时间一致的 `pending` 设备记录；用户批准该记录后，Android 15 ARM64 真机完成真实 HTTPS 取钥、载荷解密和业务 Activity 加载。首次加载约 3.206 秒，强制停止后使用已有 DEX 缓存再次启动约 2.710 秒，两个进程均未出现 JNI、取钥或未捕获启动异常，页面停留在应用自身的隐私政策确认界面。

上述两次耗时仅为启动功能回归，不是性能统计验收；未代替用户同意隐私政策，未覆盖登录、录音等后续业务，也不代表 Play 或实际 KMS/HSM 联调通过。测试 APK、进程日志和页面截图保存在同一忽略目录；源码记录不包含服务凭据、完整 token 或设备公钥标识。
