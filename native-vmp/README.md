# Mocika Native VMP（源码/LLVM bitcode 接入）

这个目录提供真实的编译期 Native 函数虚拟化路径。它把显式标注函数的 LLVM IR
翻译成自定义寄存器字节码，并把原函数体替换为 `mocika_vmp_exec_i64` 解释器入口。
产物包含 `.mocika.vmp` 段；原函数的基本块和受支持标量运算不再作为原生控制流保留。

它与 APK 后处理阶段的 PSO2 不同：PSO2 只能对已编译 ELF 的安全函数区域做认证静态
加密；Native VMP 必须在业务 Native 源码/bitcode 构建阶段接入。两者可以叠加，先在
业务 CMake 中执行 VMP，再让 `shield protect/protect-aab --profile strict` 对最终 `.so`
执行 PSO2。

## 当前契约

- 编译器和 `opt` 必须为同一 LLVM 主版本；当前锁定 LLVM 21，Android 示例使用
  NDK `29.0.14206865`。
- CMake 推荐 `-G Ninja`，自测使用 Ninja。拒绝 GNU Make 4 以前的版本（包括 macOS
  自带的 3.81），因为它可能漏掉同一秒内的工具更新。编译依赖文件另绑定 Pass 和启动器，
  工具变化会重建相关对象；GNU Make 4+ 路径仍需在相应宿主验证。
- `MOCIKA_VMP` 标注就是明确的函数白名单。没有标注的函数不会被改写。
- 支持最多 64 位的整数，以及 `float`/`double` 参数和返回值。包含整数算术/位运算，
  浮点加减乘除/余数/取反、16 种有序/无序比较、`select`、PHI、分支、switch 和循环。switch 复用 LLVM 的
  [LowerSwitch](https://llvm.org/docs/Passes.html#lowerswitch-lower-switchinsts-to-branches)
  转成比较和分支，仍受 512 个寄存器的上限约束。
- 支持整数扩展/截断、浮点扩展/截断、整数与浮点互转、同宽位转换，以及
  `llvm.fma` / `llvm.fmuladd`（使用融合计算）及有符号/无符号整数 min/max。浮点转整数越界或非有限输入失败关闭，
  不把 LLVM 的 poison 输入解释成某个正常整数。取反保持 NaN 载荷和符号位语义。
- 支持整数 `llvm.fshl` / `llvm.fshr` 漏斗移位及循环移位，复用现有 VM 整数指令。
  位移量按位宽取模，零位移和位宽倍数不会产生越界移位；语义依据
  [LLVM Language Reference](https://llvm.org/docs/LangRef.html#llvm-fshl-intrinsic)。
- 当前不支持指针参数、内存读写、通用函数调用、严格浮点环境/受约束浮点、半精度、
  向量、异常、原子/同步和可变参数。运行时拒绝以 `-ffast-math` 构建。
  任何已标注函数出现不支持语义都会让编译失败；不会静默保留原函数并宣称成功。
- 已标注函数必须是独立定义；拒绝 weak/linkonce/COMDAT（例如可能被链接器合并的
  C++ inline/模板定义）。可把受保护标量计算移入单独的非 inline 函数。
- 每个函数的虚拟 Opcode 编码默认使用构建期随机种子。设置
  `MOCIKA_VMP_SEED=<固定值>` 可以得到可复现的测试构建，但发布构建不建议固定。
- 运行时限制为每个函数最多 512 个 VM 寄存器。越界会在编译期拒绝。
- CMake 启动器拒绝 LTO、额外 Pass、隐藏阶段选项和叠加的编译启动器。无法识别输入、
  工具版本不符、响应文件循环、旧 Pass 不输出报告都会失败，不回退为普通编译。

这是一条可运行的选择性 Native VMP 链路，不是任意 C/C++ 的全语义虚拟机，也不能
用于没有源码/bitcode 的第三方 `.so`。未经过真实设备执行的 ABI/厂商格子仍应标记为
待验证。

## 构建 Pass 并自测

```bash
LLVM_CONFIG=/opt/homebrew/opt/llvm/bin/llvm-config \
  native-vmp/tests/run-self-test.sh
```

自测会：

1. 构建 LLVM Pass；
2. 编译并执行含循环/PHI/分支的等价性样本；
3. 检查生成 IR 已调用解释器，常量返回函数不会在转换前把结果传播进调用方；
4. 验证嵌套响应文件、空格路径、预包含、显式语言、固定种子和跨文件同名 static 函数；
5. 检查不支持的语义/链接形式/编译选项被拒绝，失败保留旧对象和报告；
   C 源码 switch 另做 65,536 组窄整数接口对照，限幅函数再做 256 组；
6. 生成 111 个 LLVM 函数，以边界值和固定随机输入进行 1,818,624 次原生/虚拟对照，
   覆盖 NaN、正负零、无穷、非正规数、整数转换、PHI、融合乘加，以及 8/32/64 位稠密/稀疏 switch、循环和整数 min/max，另覆盖 1/8/32/64 位左右漏斗/循环移位；`fmuladd` 按 LLVM 允许的融合/分步舍入结果判定，不使用任意误差容限；
7. 检查旧格式、截断输入、越界浮点转换拒绝，以及优化后仍存在 volatile 擦除；
8. 独立恢复器消除两次构建的位置编码并比较规范化程序，防止把格式变化当成保密。

同一套标量检查可在已授权设备执行，不安装应用，仅在 `/data/local/tmp` 使用随机文件名，
完成后清理。上传后回读探针并核对摘要；结果记录绑定 Pass、运行时、检查脚本和生成源文件，
失败不会遗留旧的成功摘要。窄整数接口的 ABI 由目标 Clang 探测，避免把 macOS/ARMv7 的
零扩展约定套到 Android ARM64。设备属性和页大小随结果保存：

```bash
python3 native-vmp/tests/check-scalars.py \
  --plugin /path/to/MocikaNativeVmpPass.dylib --llvm-bin /path/to/llvm/bin \
  --output target/native-scalars-device \
  --cc /path/to/ndk/bin/aarch64-linux-android23-clang --serial DEVICE_SERIAL
```

## 离线编码与内存边界

新编译产物使用 MVMP v2：10 字节旧头后追加 8 字节函数种子，再保存按绝对位置编码的
指令体。操作码、寄存器索引、分支目标和常量都经过位置编码；读取器逐字节解码，不
创建完整解码程序副本。旧 v1 继续可读。固定种子只用于可重复测试。

这是构建多样化，**不是密码学机密性**：种子和解码器随程序分发，独立恢复器仍可复用。
不能据此声称静态恢复被阻断。解释器在正常返回和执行失败时擦除当前/前驱寄存器数组，
生成的桥接函数在成功/失败分支前擦除参数副本；volatile 保证优化后仍执行。清理不涵盖
调用者数据、返回值、CPU 寄存器或被编译器/系统另行产生的副本，也不能阻止运行中观测。

macOS 上不能假设 Google 签名的 NDK Clang 可以直接 `dlopen` 第三方 Pass。CMake
集成使用编译启动器执行“NDK Clang 生成 bitcode → 同版本 `opt` 加载 Pass → NDK
Clang 生成对象文件”，不修改、不重签 NDK 工具。第一阶段用 `-disable-llvm-passes`
保留前端 IR，Pass 仅在标注函数内做 SSA 规范化，替换原体后才执行普通优化。
这避免原实现提前传播到调用方，也不会给所有普通函数强加 `-O0` 的 `noinline` 属性。
直接 `-fpass-plugin` 入口同样在优化管线开始时执行。

## 业务 CMake 接入

```cmake
add_library(business SHARED business.c)

include("/path/to/mocika-shield/native-vmp/cmake/MocikaNativeVmp.cmake")
mocika_enable_native_vmp(business
    PLUGIN "/path/to/MocikaNativeVmpPass.dylib"
    LLVM_OPT "/opt/homebrew/opt/llvm/bin/opt")
```

只标注高价值、满足当前语义子集的内部函数；JNI 导出函数可以保留为薄包装：

```c
#include "mocika_native_vmp.h"

MOCIKA_VMP static uint32_t protected_score(uint32_t value, uint32_t rounds) {
    uint32_t result = value;
    for (uint32_t i = 0; i < rounds; ++i) {
        result = (result * 13 + i) ^ (result >> 3);
    }
    return result;
}
```

不要直接标注带 `JNIEnv *`、对象指针或复杂库调用的 JNI 导出函数；让导出函数调用
一个只使用受支持标量语义的内部函数。完整 Android/Gradle 示例位于
`tests/fixtures/android-dynamic-feature-app/conditional_feature`。只启用 `LANGUAGES CXX`
的工程会用 C++ 编译兼容的解释器源文件，保留 C 导出，不需要另外启用 C 编译器。

## 编译、链接和打包证据

每个对象旁生成 `<对象名>.mocika-vmp.json`，记录源码/中间 bitcode/对象摘要、工具版本、
Pass/启动器摘要、配置摘要以及实际转换的符号和程序摘要。相同源码路径及固定种子下，
临时构建目录的变化不会改变虚拟程序；源码路径本身仍属于种子的输入。

Android/Linux 的 CMake 共享库、模块库和可执行目标在链接后自动生成
`<产物名>.native-vmp.json`（当前 schema 2）。核验要求：

- 当前目标全部 C/C++ 源文件有匹配的对象记录；缺失、重复、旧工具记录或源码变化均拒绝。
- 每个转换函数在最终 ELF 中存在，字节码摘要一致，实际函数包含到解释器的直接调用。
- 报告绑定 ELF 加载头、段权限、加载段全部字节以及可加载节；不能只靠 `.mocika.vmp`
  节存在宣称成功。至少一个函数实际转换并链接，否则启用该目标保护的构建失败。

schema 2 的 `load_image.sha256` 使用可移植算法：清零 ELF 头中的节表位置、项大小、
数量与名称索引，将规范化 ELF 头、原始程序头表、各 `PT_LOAD` 的 32 字节 SHA-256
按顺序拼接后再摘要；加载段与 ELF 头重叠的部分也使用规范化头。其余加载字节不变。
桌面核心可以直接核验，无需用户安装 LLVM 或 Python。旧 schema 1 链接报告须重新
生成，不能只修改版本字段；对象级编译记录仍使用自身的 schema 1。

符号剥离可以改变非加载节和节表位置，不能改变代码/数据/加载行为。保留可信的构建
报告后，可验证剥离后的 `.so`，也可验证 APK/AAB 中任意模块的精确条目：

```bash
python3 native-vmp/cmake/mocika_vmp_evidence.py verify \
  --readobj /opt/homebrew/opt/llvm/bin/llvm-readobj \
  --report /path/to/libbusiness.so.native-vmp.json \
  --library /path/to/stripped/libbusiness.so

python3 native-vmp/cmake/mocika_vmp_evidence.py verify \
  --readobj /opt/homebrew/opt/llvm/bin/llvm-readobj \
  --report /path/to/libbusiness.so.native-vmp.json \
  --archive /path/to/app.aab --entry feature/lib/arm64-v8a/libbusiness.so
```

APK 的条目通常为 `lib/<abi>/<库名>.so`。重复/缺失条目、ABI 不符或加载内容变化均拒绝。
单库核验预算为 512 MiB，报告为 16 MiB。PSO2 会改写 ELF 加载内容，因此须在 PSO2
加密前核验并保存 Native 构建记录；独立 SDK 验证器不会把加密后的不同字节认成同一库。

这些是本地构建记录，依赖可信工具链和报告，不是签名证明或对恶意编译器的防护。
`linked_verified` 表示转换和链接核验通过，`execution=not_recorded` 明确表示没有设备
执行证据。

## CLI / GUI 接入与最终产物核验

准备 UTF-8 TSV 清单，每行包含一个库条目和对应链接报告路径，中间为真实制表符：

```text
base/lib/arm64-v8a/libbusiness.so	build/arm64-v8a/libbusiness.so.native-vmp.json
feature_rules/lib/arm64-v8a/librules.so	build/arm64-v8a/librules.so.native-vmp.json
```

普通 APK 只使用 `base`；AAB 使用实际模块名。报告路径相对 TSV 所在目录解析，也支持
绝对路径；允许空行和 `#` 注释。不同 ABI 分别列出，不能把一个架构的报告复用于其他架构。
清单最多 1024 个条目、1 MiB，报告合计最多 64 MiB；空清单、重复、缺失、错误 ABI、
过期证据以及排除必验库 ABI 的配置都会失败。

```bash
shield protect --input input.apk --output protected.apk \
  --native-vmp-evidence native-evidence.tsv
```

`protect-aab --engine mocika` 接受同一参数，保留原有 AAB 工具、签名与多模块保护要求。
CLI 的 APK 配置可在 `[protect]` 中设置 `native_vmp_evidence`，相对路径基于配置文件目录。
GUI 的 APK 与 AAB 加固页均可选择“Native 构建证据清单（可选）”。只核验 Native 证据时无需
额外选择 Java/Kotlin 方法；叠加 PSO2 仍沿用 strict + PVM2 的既有配置。

成功后输出旁的 `.protection.json` 包含 `native_vmp` 数组，每项记录精确模块条目、输入/
输出库摘要、原始构建报告及其摘要。库未改写时标为 `unchanged`；PSO2 改写时，Packer
重新读取落盘 ELF 的函数范围并解密，完整还原字节必须与输入一致，才可记为
`pso2_roundtrip_verified`，同时绑定运行时密钥表摘要。报告不含该密钥表本身或密钥明文。
最终 APK 打包、AAB 重组以及 Shellsmith 签名均重新比对库和密钥表，再绑定最终文件摘要。
无 PVM2 时报告中的 PVM2 版本为 0、方法列表为空，不产生 Java/Kotlin 覆盖率保证。

这是可信本地构建链的核验；还原检查不是设备加载或执行测试，构建记录的
`execution=not_recorded` 始终保留。清单以外的 Native 库不计入 VMP 覆盖，也不会自动
获得虚拟化能力。使用外部工具改包或签名后，应重新走对应核验流程。

## 已验证构建范围

已验证的构建路径为 macOS LLVM 21、NDK r29、Ninja/Unix Makefiles。Windows 响应文件
使用宿主 Windows 解析 API，但尚未做原生 Windows 构建验证。静态库/OBJECT 目标和
Mach-O 目前只有编译记录，没有最终 ELF 证明；跨静态库聚合、Unity、多配置生成器
不在当前验收范围。需将受保护源文件纳入最终目标，不能把独立预编译库自动算入覆盖率。
工具内容变更会触发 CMake 重新配置，并通过编译参数中的工具摘要让全部 C/C++ 源重编译，
包括生成器表达式中的条件源与接入后追加的源。Ninja 和 Unix Makefiles 的增量检查覆盖此路径；
仍有旧记录时最终链接核验会拒绝。

## Android 验证

对任意已生成证据的 Android 样本库，执行构建契约检查：

```bash
python3 native-vmp/tests/check-build.py \
  --plugin /path/to/MocikaNativeVmpPass.dylib \
  --llvm-bin /opt/homebrew/opt/llvm/bin \
  --library /path/to/libmocikaconditional.so \
  --report /path/to/libmocikaconditional.so.native-vmp.json
```

该检查同时覆盖剥离、归档、代码/加载头篡改、旧工具记录和缺失记录拒绝。四 ABI 的
构建结果不能代替设备执行。仓库 `conditional_feature` 样本有单独的设备检查：

```bash
python3 native-vmp/tests/check-device.py \
  --serial DEVICE_SERIAL \
  --cc "$ANDROID_NDK_ROOT/toolchains/llvm/prebuilt/darwin-x86_64/bin/aarch64-linux-android21-clang" \
  --llvm-bin /opt/homebrew/opt/llvm/bin \
  --library /path/to/libmocikaconditional.so \
  --report /path/to/libmocikaconditional.so.native-vmp.json \
  --output /path/to/arm64-device.json
```

脚本先核验库，再编译 Native 探针，上传至独立临时目录并确认设备文件摘要。探针实际
加载库并调用 JNI 薄包装，比较 1000 组输入，再以 8 线程各执行 1000 次。它不安装应用，
结束清理自己的目录。执行记录绑定库/链接报告/探针摘要和设备信息，只覆盖该整数样本，
不算 ART、应用生命周期、厂商兼容矩阵或性能验收。

2026-10-14 已在 HONOR BRP-AN00（Android 15 / API 35、4 KB 页）通过 ARM64 和 ARM32
上述探针。另以独立包名运行仓库动态模块样本，ARM64 的 Native VMP + PVM2 + PSO2
组合包通过 JNI 返回值、冷启动/重入、覆盖安装、清数据和全新安装检查；实际安装的
split、Native 密文库及密钥表均与构建产物一致。执行结果独立于构建报告保存，详见
[单机回归说明](../tests/README.md#native-单机应用回归)，不外推到未测试的设备范围。

## 已有 LLVM bitcode 接入

输入 `.bc` 已包含 `mocika_vmp` annotation，且尚未进行跨函数优化时，也可以直接运行
同一个 Pass。已经内联或传播到调用方的原始逻辑，后置 Pass 无法撤回：

```bash
/opt/homebrew/opt/llvm/bin/opt \
  -load-pass-plugin=/path/to/MocikaNativeVmpPass.dylib \
  -passes=mocika-native-vmp input.bc -o protected.bc
```

随后用目标 NDK Clang 把 `protected.bc` 与 `runtime/mocika_native_vmp.c` 一起链接。Pass、
`opt` 与产生输入 bitcode 的 Clang 必须使用兼容的 LLVM bitcode 版本；不兼容时应停止
构建，不能退回未虚拟化对象文件。
