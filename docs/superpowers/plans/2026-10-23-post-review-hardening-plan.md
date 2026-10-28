# 2026-10-23 评审后：状态收口与能力改进计划

## 背景

2026-10-23 对 v1.9.0 现状与 XopProtector 分支做了一轮复盘，确认上一轮分析的四个结论错误与两处状态过期，并以仓库证据修正：

1. **BYOS per-device wrapping 不阻断"单设备 IKM 泄漏 → 同产物全体可解"**：同一产物所有设备最终领取的是同一把 IKM，用设备公钥再包一层不改变该结果；设备密钥当前为 sign-only（`shield-stub/src/byosDevice/java/dev/mocika/shield/loader/ByosProof.java:50`，`PURPOSE_SIGN`，不能 ECDH/ECIES）。唯一真正阻断该威胁的是 per-device payload key，属架构级改动。
2. **apktool 3.0.1 路径穿越已收口**：f1979f9（2026-10-12）升级至 3.0.3 并固定分发物哈希，`scripts/check-release-ready.sh:102-127` 校验版本、SHA-256 并拒绝 3.0.1 残留。真正剩余缺口是 CI 无 cargo-audit / cargo-deny / dependabot 类依赖扫描。
3. **NativeIntegrity 已覆盖双路径**：`shield-stub/src/main/java/dev/mocika/shield/loader/NativeIntegrity.java` 的 `verifyResolvedLibrary` 对 `findLibrary` 解析出的实际路径同时覆盖 APK 内 `!/` 条目（含 ABI split APK）与解压目录文件。真实剩余问题只有加载顺序：`Ld.java` 的 static 块先 `System.loadLibrary`，`RuntimeSecurity` 后置调用 verify，被替换的 `.so` 有机会先执行。该项只能按"检测增强 + 残余风险"表述，`.so` 内 constructor 自校验不构成新的信任根。
4. **XopProtector 状态**：本地 HEAD `e408b87`（2026-09-19），`origin/main` 已为 `4a41d0b`（2026-10-20），落后 5 个提交；工作区另有 22 文件未提交 diff（+1614/-237）；`third_party/xopprotector` 为部分 vendoring（无 `dex/` 目录），已独立演进到镜像 v9，`pvm2_interp.cpp:902` 的 contextClassLoader 解析与 MUTF-8 处理领先本地分支。

本计划不含"防静态恢复""防内存提取"类承诺；涉及能力描述的改动一律按 `docs/process/roadmap.md`「评估口径」给证据。

---

## 批次〇：合入 TheRouter 编译期注册兼容（补丁版候选，约 0.5 天）

已确认问题（本次评审中定位）：TheRouter 走 Gradle 插件 ASM 编译期注册时，kapt 只生成 `a/ServiceProvider__TheRouter__<hash>` 等生成类而不生成运行时索引持有类，`crates/shield-core/src/protect/dex.rs` 现行 main 代码在此时以「扫描到 TheRouter 生成类，但未找到运行时索引持有类」硬报错，加固流程中断。实锤样本为多模块 kapt 应用（module-file 变体）。

修复分支 `fix/therouter-registration-compat`（提交 343bc31，基于 1.8.6）已完成：route_scanner 解析 `TheRouterServiceProvideInjecter` 的 `asm` 静态字段判定注册模式三态；dex.rs 改为「编译期注册→跳过 / 无生成类→跳过 / 两者皆不明→`THEROUTER_REGISTRATION_UNRESOLVED` 明确拒绝并附排查指引」；新增 `tests/scripts/check-therouter-compat.py`（asm/index/unknown 三模式）。

### 任务
1. `fetch` 后确认 `git merge-tree` 预检仍为零冲突（2026-10-23 预检通过），合入 `fix/therouter-registration-compat`。
2. 回归：`check-therouter-compat.py` 三态全跑；无 TheRouter 应用（smoke 本线）、索引回退样例（假产物）各一次；真实多模块样本真机路由跳转一次。
3. 1.9.1 补丁发布；issue-ledger 登记（TheRouter ASM 注册模式此前在台账与 roadmap 均无条目）。
4. 与批次三（路由 assets 保护）的衔接：编译期注册分支不产生索引资产，索引回退分支产生；批次三验收两种模式都要覆盖。

### 退出条件
1.9.1 发布；后续主线再无「生成类存在但要求索引持有类」的硬报错路径。

---

## 批次一：状态收口与依赖扫描（文档/CI，无运行时改动，约 1 天）

### 任务

1. `docs/process/roadmap.md` 对齐：
   - 基线 `1.8.0` → `1.9.0`（`crates/shield-core/Cargo.toml`、`apps/shield-cli/Cargo.toml` 均为 1.9.0，2026-10-21 已发布）。
   - 「待修」表的 apktool 条目移入「已收口」；同步写入哈希固定与发布门禁事实。
   - 「待修」壳库完整性条目改述：双路径已覆盖，剩余问题仅加载顺序；给出"检测增强"定位与残余风险说明，并同步 `docs/design/runtime-security.md`。
2. 依赖扫描落地（现状 `.github/` 无任何扫描配置）：
   - 新增 `.github/dependabot.yml`（cargo、npm、gradle）。
   - CLI 增 `cargo-deny`（advisories + unmaintained 起步），CI 只告警不阻断发布，观察一轮收紧阈值。
3. 文档提交不触发版本号变更。

### 提交拆分

- `docs: 与 v1.9.0 现状对齐路线图安全态势`
- `docs: 补充壳库加载顺序残余风险说明`
- `ci: 接入依赖漏洞扫描`
- `build: 添加 cargo deny 配置`

### 退出条件

roadmap 中不再存在与 v1.9.0 现状矛盾的描述；CI 出现依赖扫描任务且首个告警有处理记录。

---

## 批次二：XopProtector 分支审计与收编（不进发布链，约 2–3 天）

### 实测基线

- 本地 HEAD `e408b87`（支付 True-VMP 实验线）；`origin/main = 4a41d0b`，落后 5 提交、36 文件、+5657/-692（主题：SO 冷启动策略 L2e、Dobby ARM64 重定位增强、shadowhook 2.0.1、16KB 页对齐、business_so.cpp 大改）。
- 工作区未提交 diff：22 文件；与 origin 五提交在 6 个文件上重叠（`dex_file.cpp`、`ReadElf.java`、`TrueVmpTrampoline.java`、`PackerMain.java`、`BusinessSoProtector.java`、`build.gradle.kts`），**直接 rebase 必冲突**，须按主题拆分裁决。
- `third_party/xopprotector` 自 vendoring 起（`e408b87` 基底）已演进到镜像 v9（v6 寄存器置换、v7 逐方法清理、v8 参数类型表、v9 invoke-super）。

### 任务

1. `git fetch` 后以 `e408b87..origin/main` 为主线逐提交归档结论，确认 origin 五提交无 PVM2 格式变更（origin `pvm2_format.h` 只到 V5）。
2. 工作区未提交 diff 按主题定案，产出三栏台账（保留→动作 / 丢弃→理由 / 送上游→PR）：
   - `dex_file.cpp` SHA-1 `bit_len` `size_t`→`uint64_t`：origin/main `:1032` 仍为 `size_t`，32 位 ABI 下超过 2^29 字节 DEX 长度位溢出成立，修复独有且正确 → 以上游 PR 提交 origin（third_party 不编译 `dex/`，不影响 Shellsmith）。
   - PVM2 v6 未提交工作（寄存器置换 1:1 校验、catch handler priority 10 字节、`interpret_body<DispatchVariant>` 三变体 dispatch 密钥流）：origin 只有 V5，third_party 的 v6 为独立演进。逐项对照 third_party 的 v6–v9 语义裁决；若重复实现则丢弃；dispatch 密钥流作为候选增量，但纳入 third_party 必须走镜像格式版本门禁与本仓库通用增改验收（原始/转换版本结果对照、异常路径对照）。
   - `find_class_desc` contextClassLoader 修复：third_party `pvm2_interp.cpp:902` 已领先（另有 `string_from_utf8` MUTF-8 处理），丢弃。
   - `build.gradle.kts` `exportShellFiles` 稳健化：对照 origin 当前实现后定案。
3. 台账完成后定目录去留：third_party 为准归档独立壳线，或保留为支付 True-VMP 实验线并在 docs 标注维护边界。
4. 台账写入本仓库文档；不再维持 local / origin / third_party 三方同文件各自演进的未对账状态。

### 退出条件

工作区 `git status` 不再有未裁决 diff；台账文档合入；上游 PR 链接记录在案。

---

## 批次三：路由 assets 保护（主题版本目标：下一个小版本）

### 关键架构事实（已核实，影响方案可行性）

- `assets/arouter_routes.txt` 与 `assets/therouter_registry.txt` 由加固器产出（`crates/shield-core/src/protect/dex.rs:46-67`，`route_scanner` 扫描解密后 DEX），**消费方是壳自己的** `ARouterCompat` / `TheRouterCompat`（`shield-stub/src/main/java/dev/mocika/shield/loader/`）：读文件 → 写 ARouter 自有缓存（`SP_AROUTER_CACHE`）→ 之后 ARouter 走正常流程按需加载路由类。
- 因此"加密后第三方框架读不了"的顾虑不成立：读文件的是壳自身代码，可以改为解密后内存喂入，不经过 Hook 与第三方行为改造。
- 明确本项定位：提高自动化静态分析首段成本（JADX 等工具在加固 APK 上可直接读到的路由索引消失，必须先实现 DEXB 解密链）；**不改变** DEXB v6/v7 的机密性边界，不作为"防静态恢复"证据。

### 设计

1. 打包端：`route_scanner` 产物不再写明文 assets。序列化（含 zstd）后随既有加密边界分发——首选并入现有加密 sidecar 结构或 DEXB 载荷尾部新版本块（实现时二选一定稿，带格式版本号与旧包兼容规则）；密钥复用 dex 域 HKDF 子域分隔（新增 info 区分），不引入第二套密钥管理。
2. 壳端：解密完成后由 stub 把路由表喂给 `ARouterCompat` / `TheRouterCompat`（内存路径），删除 assets 明文读取分支；旧包缺新块时回退现行为（兼容路径保留一个版本周期，之后在 Release Notes 宣布不再兼容旧包）。
3. 诊断与文档：protection 报告、`docs/usage.md`、`docs/design/internals.md` 同步；报告不再出现明文路由路径。

### 时序风险（实现前先验证）

`ARouterCompat.prepareARouterRouteMap` 的约束是"宿主 Application.onCreate() 之前调用"：需确认 stub 解密完成点先于该调用点（现有流程 DexCache/DexInjector 时序），在 API 19 线（`compat/api19-rust` + Element 工厂路径）单独验证一次。

### 验收

- E2E：`tests/fixtures/android-smoke-app`（含 ARouter/TheRouter 模块）加固后断言输出 APK 中不存在两个明文 assets；加固前后路由跳转语义一致。
- 兼容：API 19 线一次；`extractNativeLibs` 两态；BYOS（v7）路径一次。
- 现有契约脚本保持全绿：`check-pvm2-art.py`（默认基线）、`run-protect-e2e.sh`；新增"禁明文路由 assets"断言进 E2E。
- 真机：沿用 `measure-apk-acceptance.py` 与设备矩阵流程采样一轮，绑定新产物摘要。

### 退出条件

主题版本发布；Release Notes 与砍口（兼容范围变化）同步；`check-rea-resilience.py` 批次前后各复跑一轮，恢复步骤数变化如实记录。

---

## 批次四：BYOS 威胁模型与边界固化（文档为主，约 2 天）

产出 `docs/design/byos-key-model.md`，逐威胁×对策×边界：

1. **已覆盖**：响应密文侧（每请求临时 RSA-2048 响应密钥 + OAEP-SHA256 包裹 + digest 前缀校验 + nonce 回显 + 时间窗，`ByosKeyClient.java:109-171`）；服务端生命周期（`devices` 表审批/吊销/expiry、KMS 四 backend、admin 审计）。
2. **明确边界（不排期）**：单设备 IKM 明文泄漏（内存提取/Frida）→ 同产物全体可解；唯一解法是 per-device payload key（按设备产物或服务端送载荷），与商店分发及默认离线原则冲突，记录为已评估不采纳的架构级方向。
3. **运维要求**：服务端明文 `net.Listen` 依赖反向代理 TLS（`main.go:150` + `deploy/Caddyfile.example`）；Play Integrity 模式依赖 Google API 可达性列为可用性限制；部署 checklist 进 key server README。
4. 与 `docs/process/roadmap.md`「待考虑」口径互相引用收敛，避免再次出现两处口径漂移。

### 退出条件

文档合入；无行为变更提交。

---

## 批次五：验证与性能采样（贯穿各批次）

1. 每个进行中的批次完成后跑一次 `measure-apk-acceptance.py`（冷启动/PSS/方法探针）+ `run-device-matrix.sh` 既定范围，绑定产物摘要，不跨批次复用旧成绩。
2. REA 口径：`check-rea-resilience.py` 在能改变分析首段成本的批次前后各跑一轮，工具版本与输入哈希照旧记录；语义重建与动态注入维持"未验证"标记。
3. 每阶段保留同一套可运行回归；失败样本与温控中断证据照旧保留，不清洗。

---

## 中期（条件驱动，不进本计划排期）

1. DEX 字符串池混淆：在批次三落地后单独立项评估（两者是不同泄漏面，不能合并：assets 是壳自有文件、字符串池在 DEX 内），验收以启动耗时与 ARouter/TheRouter 回归为准。
2. iOS 三管道缺陷（freeRASP 只通知不阻断、注入不注册回调、Swift Confidential 静默跳过）：修复可在补丁线单独发版，这是 iOS 侧一切后续能力的先决条件。
3. PVM2 长尾 opcode（`sparse-switch`、`goto/32`、`move/16` 系）：先统计授权样本集内的实际出现频率，频率证据不支持就不动镜像版本。

## 版本策略

- 批次一/二/四：文档与 CI 提交，不出版本。
- 批次三：走下一个功能版本，一个小版本聚焦一个主题；涉及加密边界与入口格式，必须带格式版本号与旧包回退路径。
- 遵循 `docs/process/commit-convention.md` 与仓库既有约定；提交不复述内部编号。
