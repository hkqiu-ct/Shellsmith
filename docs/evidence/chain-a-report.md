# Chain A 报告：DEXB + PVM2 静态恢复成本

状态：`baseline`。本文只记录已有证据与待验证项，不把历史样本外推为当前版本结论。

## 1. 历史基线（来自已有 REA/代码保护记录）

| 项目 | 结果 | 样本范围 |
|---|---|---|
| 选中 PVM2 方法 | 54,249 | 单个授权真实 APK |
| 通过产物核验 | 11,613 | 同一 APK |
| 总方法覆盖 | 21.41% | 仅该样本 |
| 指令字节覆盖 | 30.52% | 仅该样本 |
| 指定必保测试范围 | 19/19 | 不代表完整关键业务 |
| 三次独立构建 | 字节不同，11,613 个规范化指令摘要相同 | 同一恢复器可复用 |
| 启动中位数增量 | 约 +44.49% | 单台 HONOR Android 15 |
| PSS 增量 | 约 +11.91 MiB | 单台设备、启动后 1 秒 |

## 2. 当前可验证结论

- DEXB v6 的包内材料足以离线恢复载荷；这是明确边界，不是缺陷。
- PVM2 能提高语义分析成本，但已有白盒恢复器可以跨构建复用；字节变化不等于抗恢复。
- 必保方法核验是发布门槛；总覆盖率不能替代关键业务覆盖。
- 路由 assets 加密已实现为 opt-in，可减少静态分析首段可见索引，但不改变 DEXB 机密性边界。

## 3. 待执行实验

| ID | 实验 | 失败条件 |
|---|---|---|
| A-01 | 当前产物清单与哈希 | 缺失/不可追溯 |
| A-06 | 原包/加固包差分 | 任一 P0/P1 语义差异 |
| A-07 | 运行时明文采样 | 无法定位/清理窗口 |
| A-08 | 启动/PSS 预算 | 超过预注册预算 |

## 4. 未验证项

- 当前版本在真实业务 APK 上的覆盖率与恢复成本。
- 跨设备、跨 ROM、跨 ABI 的语义等价。
- REA/Frida 的真实动态注入与完整语义重建。
- 路由 assets `.rtap` 的真机运行验证（当前设备 PackageManager 异常）。

## 4.1 2026-10-28 真机追加验证

| 项目 | 结果 |
|---|---|
| 设备 | HONOR BRP-AN00，Android 15 / API 35，arm64-v8a |
| 测试 | `python3 tests/scripts/check-therouter-compat.py --cli target/release/shield --serial AASEVB5730002067` |
| TheRouter asm 模式 | 加固、签名、注册、PVM2 通过 |
| TheRouter index 模式 | 加固、签名、注册、PVM2 通过；产物只含 `therouter_registry.rtap`，无 `.txt` |
| ARouter | 产物只含 `arouter_routes.rtap`，无 `.txt` |
| 未知注册模式 | 保持拒绝 |
| 状态 | `verified`（仅该设备、该模拟样本） |

该结果只证明路由 assets 加密和 TheRouter 兼容在该设备/样本上运行通过，不代表所有 ROM、所有业务路由或所有 PVM2 方法均已验证。

## 4.2 2026-10-28 真机 E2E 追加验证

| 项目 | 结果 |
|---|---|
| 设备 | HONOR BRP-AN00，Android 15 / API 35，arm64-v8a |
| 基础 E2E | `RUN_DEVICE_TEST=1 bash tests/scripts/run-protect-e2e.sh`：双 DEX 基线、加固包首次启动、缓存启动、Native、openFd、secondary 全部通过 |
| 严格 E2E | 追加 `PVM2_STRICT_TEST=1`：54/54 方法转换、PAS2 1 个文件、PSO2 4 个 ABI、PVM2 ISA 2；首次启动与缓存启动通过 |
| 状态 | `verified`（仅该设备、该 smoke 样本） |

该结果证明 Shellsmith 单 Stub、DEXB、PVM2、PAS2、PSO2 和 Native 加载链路在该样本上可运行，不代表所有业务 APK、ROM 或 ABI 均已验证。

## 5. 停止条件

- 如果恢复成本没有显著提高，停止继续增加格式复杂度。
- 如果差分测试出现不可接受的语义差异，停止扩大 PVM2 覆盖。
- 如果性能超出预算，停止增加运行时检查/加密层。
