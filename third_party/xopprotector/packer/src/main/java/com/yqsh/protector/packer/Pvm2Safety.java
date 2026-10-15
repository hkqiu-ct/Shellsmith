package com.yqsh.protector.packer;

import com.android.dex.Code;
import com.android.tools.smali.dexlib2.Opcode;
import com.android.tools.smali.dexlib2.Opcodes;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Conservative, package-agnostic admission checks for PVM2 methods.
 *
 * <p>The interpreter intentionally throws the same NPE as ART when an invoke
 * receiver is null.  That is correct VM behaviour, but a static transform must
 * not move a method into PVM2 when it cannot prove the receiver's nullability.
 * This checker keeps the non-null instance receiver and proven non-null branch
 * paths compatible with ART.  At control-flow joins it intersects facts from
 * all incoming paths; unknown receivers crossing a branch or exception edge
 * stay on ART, where verifier and handler semantics remain authoritative.</p>
 */
final class Pvm2Safety {
    private static final Opcodes OPCODES = Opcodes.getDefault();

    private Pvm2Safety() {
    }

    static String check(Code code, boolean isStatic) {
        if (code == null) return "semantic safety: no code";
        short[] units = code.getInstructions();
        ExceptionalInfo exceptional = exceptionalBoundaries(code, units);
        return checkInternal(units, code.getRegistersSize(), code.getInsSize(), isStatic,
                exceptional, false);
    }

    static String check(short[] units, int registersSize, int insSize,
                        boolean isStatic, boolean hasExceptionalFlow) {
        return checkInternal(units, registersSize, insSize, isStatic, null,
                hasExceptionalFlow);
    }

    private static String checkInternal(short[] units, int registersSize, int insSize,
                                        boolean isStatic, ExceptionalInfo exceptional,
                                        boolean hasExceptionalFlow) {
        if (exceptional != null && exceptional.invalid) return "semantic safety: malformed exception table";
        if (units == null || units.length == 0) return null;
        if (registersSize <= 0 || registersSize > 255) {
            return "semantic safety: invalid register frame";
        }
        Map<Integer, Integer> widths = new HashMap<>();
        int pc = 0;
        while (pc < units.length) {
            int op = units[pc] & 0xff;
            int width;
            try {
                width = widthOf(units, pc, op);
            } catch (RuntimeException ex) {
                return "semantic safety: malformed instruction";
            }
            if (width <= 0 || pc + width > units.length) {
                return "semantic safety: malformed instruction";
            }
            widths.put(pc, width);
            pc += width;
        }
        if (pc != units.length || widths.isEmpty()) return "semantic safety: malformed instruction";

        FlowState initial = new FlowState(registersSize);
        int thisReg = registersSize - Math.max(insSize, 0);
        if (!isStatic && insSize > 0 && thisReg >= 0 && thisReg < registersSize) {
            initial.knownNonNull[thisReg] = true;
        }

        Map<Integer, FlowState> inStates = new HashMap<>();
        ArrayDeque<Integer> pending = new ArrayDeque<>();
        inStates.put(0, initial);
        pending.add(0);

        while (!pending.isEmpty()) {
            pc = pending.removeFirst();
            Integer widthValue = widths.get(pc);
            if (widthValue == null) return "semantic safety: malformed branch target";
            int width = widthValue;
            int u0 = units[pc] & 0xffff;
            int op = u0 & 0xff;
            FlowState state = inStates.get(pc).copy();
            if (exceptional != null && pc < exceptional.inTry.length
                    && (exceptional.inTry[pc] || exceptional.handler[pc])) {
                state.controlFlow = true;
            } else if (exceptional == null && hasExceptionalFlow) {
                state.controlFlow = true;
            }

            // 异常边读取执行前的事实，不能继承解引用正常完成后的非空结论。
            Opcode metadata = OPCODES.getOpcodeByValue(op);
            if (exceptional != null && metadata != null && metadata.canThrow()) {
                for (int handlerPc : exceptional.targets.getOrDefault(pc, List.of())) {
                    if (!widths.containsKey(handlerPc)) return "semantic safety: malformed exception target";
                    FlowState thrown = state.copy();
                    thrown.controlFlow = true;
                    // ponytail: 写目标在异常边保守作废，避免依赖 JNI 失败前是否已写入；精确放行需逐指令证明。
                    if (metadata.setsRegister() && op != 0x1f) {
                        int destination = destination(metadata, u0, units, pc);
                        clearKnown(destination, thrown.knownNonNull);
                        thrown.forgetTypeTest(destination);
                        if (metadata.setsWideRegister()) {
                            clearKnown(destination + 1, thrown.knownNonNull);
                            thrown.forgetTypeTest(destination + 1);
                        }
                    }
                    if (mergeState(inStates, handlerPc, thrown)) pending.addLast(handlerPc);
                }
            }

            if (requiresReceiver(op)) {
                int argc = isInvoke35(op) ? (u0 >>> 12) & 0x0f : (u0 >>> 8) & 0xff;
                if (argc == 0) {
                    return isInvoke35(op)
                            ? "semantic safety: invoke missing receiver"
                            : "semantic safety: invoke/range missing receiver";
                }
                int receiver = isInvoke35(op)
                        ? (units[pc + 2] & 0xffff) & 0x0f
                        : units[pc + 2] & 0xffff;
                String reason = receiverReason(receiver, state.knownNonNull, state.controlFlow);
                if (reason != null) return reason;
                // 调用正常返回后接收者必非空；异常边已在执行前传播。
                state.knownNonNull[receiver] = true;
            }

            // 字段/数组访问正常完成后，其对象必非空；先记录，再处理可能覆盖对象的目标寄存器。
            if (op == 0x21 || (op >= 0x52 && op <= 0x5f)) {
                setKnown((u0 >>> 12) & 0x0f, state.knownNonNull, true);
            } else if (op >= 0x44 && op <= 0x51) {
                setKnown(units[pc + 1] & 0xff, state.knownNonNull, true);
            }
            if (metadata != null && metadata.setsRegister() && op != 0x1f) {
                int destination = destination(metadata, u0, units, pc);
                state.forgetTypeTest(destination);
                if (metadata.setsWideRegister()) state.forgetTypeTest(destination + 1);
                int source = (u0 >>> 12) & 0x0f;
                if (op == 0x20 && source != destination && source < registersSize && destination < registersSize)
                    state.typeTestSource[destination] = source;
            }
            updateKnownNonNull(op, u0, units, pc, state.knownNonNull);
            for (Successor successor : successors(units, pc, op, width, state, widths)) {
                if (!widths.containsKey(successor.pc)) {
                    return "semantic safety: malformed branch target";
                }
                if (mergeState(inStates, successor.pc, successor.state)) {
                    pending.addLast(successor.pc);
                }
            }
        }
        return null;
    }

    private static String receiverReason(int receiver, boolean[] knownNonNull,
                                         boolean hasControlFlow) {
        if (receiver < 0 || receiver >= knownNonNull.length) {
            return "semantic safety: receiver register out of range";
        }
        if (knownNonNull[receiver]) return null;
        // ART and the interpreter both throw NPE for a null receiver in
        // straight-line code, so this does not change observable semantics.
        // The risky case is a nullable value crossing a branch/handler, where
        // PVM2 must not approximate ART's verifier and exception edges.
        if (!hasControlFlow) return null;
        return "nullable receiver with control flow";
    }

    private static boolean requiresReceiver(int op) {
        // invoke-static and invoke-static/range have no receiver.  Treating
        // their first argument as one unnecessarily rejected safe methods.
        return (op >= 0x6e && op <= 0x72 && op != 0x71)
                || (op >= 0x74 && op <= 0x78 && op != 0x77);
    }

    private static boolean mergeState(Map<Integer, FlowState> states, int pc, FlowState incoming) {
        FlowState existing = states.get(pc);
        if (existing == null) {
            states.put(pc, incoming.copy());
            return true;
        }
        boolean changed = existing.controlFlow != (existing.controlFlow || incoming.controlFlow);
        existing.controlFlow |= incoming.controlFlow;
        for (int i = 0; i < existing.knownNonNull.length; i++) {
            boolean merged = existing.knownNonNull[i] && incoming.knownNonNull[i];
            changed |= existing.knownNonNull[i] != merged;
            existing.knownNonNull[i] = merged;
            if (existing.typeTestSource[i] != incoming.typeTestSource[i] && existing.typeTestSource[i] != -1) {
                existing.typeTestSource[i] = -1;
                changed = true;
            }
        }
        return changed;
    }

    private static List<Successor> successors(short[] units, int pc, int op, int width,
                                               FlowState state, Map<Integer, Integer> widths) {
        List<Successor> out = new ArrayList<>(2);
        if (isReturnOrThrow(op)) return out;

        if (isIf(op)) {
            int target = pc + signed16(units[pc + 1]);
            FlowState targetState = state.copy();
            FlowState fallthroughState = state.copy();
            targetState.controlFlow = true;
            fallthroughState.controlFlow = true;
            int register = (units[pc] >>> 8) & 0xff;
            // instanceof 为真保证源对象非空；只保留尚未被改写的直接关系。
            if ((op == 0x38 || op == 0x39) && register < state.typeTestSource.length) {
                int source = state.typeTestSource[register];
                if (source >= 0) setKnown(source,
                        (op == 0x38 ? fallthroughState : targetState).knownNonNull, true);
            }
            // ponytail: 仅传播当前等值边的非空事实；跨指令关系需另建别名分析。
            if (op == 0x38) { // if-eqz: fallthrough is the non-null path.
                setKnown(register, fallthroughState.knownNonNull, true);
            } else if (op == 0x39) { // if-nez: target is the non-null path.
                setKnown(register, targetState.knownNonNull, true);
            } else if (op == 0x32 || op == 0x33) {
                int left = register & 0x0f, right = register >>> 4;
                FlowState equal = op == 0x32 ? targetState : fallthroughState;
                if (left < equal.knownNonNull.length && right < equal.knownNonNull.length
                        && (equal.knownNonNull[left] || equal.knownNonNull[right])) {
                    equal.knownNonNull[left] = equal.knownNonNull[right] = true;
                }
            }
            out.add(new Successor(target, targetState));
            if (widths.containsKey(pc + width)) {
                out.add(new Successor(pc + width, fallthroughState));
            }
            return out;
        }

        if (isGoto(op)) {
            int target = pc + gotoOffset(units, pc, op);
            state.controlFlow = true;
            out.add(new Successor(target, state));
            return out;
        }

        if (op == 0x2b || op == 0x2c) {
            // Switch targets are all control-flow edges.  Decode them here so
            // a receiver used only from a case is not missed by the analysis.
            state.controlFlow = true;
            int payload = pc + signed32(units[pc + 1], units[pc + 2]);
            addSwitchTargets(units, pc, payload, state, out);
            if (widths.containsKey(pc + width)) {
                out.add(new Successor(pc + width, state.copy()));
            }
            return out;
        }

        if (isControlFlow(op)) state.controlFlow = true;
        if (widths.containsKey(pc + width)) out.add(new Successor(pc + width, state));
        return out;
    }

    private static void addSwitchTargets(short[] units, int switchPc, int payload, FlowState state,
                                         List<Successor> out) {
        if (payload < 0 || payload + 1 >= units.length) {
            out.add(new Successor(-1, state.copy()));
            return;
        }
        int ident = units[payload] & 0xffff;
        int size = units[payload + 1] & 0xffff;
        if (ident == 0x0100) {
            int base = payload + 4;
            if (base < 0 || base > units.length || size > (units.length - base) / 2) {
                out.add(new Successor(-1, state.copy()));
                return;
            }
            for (int i = 0; i < size; i++) {
                int off = signed32(units[base + i * 2], units[base + i * 2 + 1]);
                out.add(new Successor(switchPc + off, state.copy()));
            }
        } else if (ident == 0x0200) {
            int base = payload + 2 + size * 2;
            if (base < 0 || base > units.length || size > (units.length - base) / 2
                    || payload + 2 > units.length || size > (units.length - payload - 2) / 4) {
                out.add(new Successor(-1, state.copy()));
                return;
            }
            for (int i = 0; i < size; i++) {
                int off = signed32(units[base + i * 2], units[base + i * 2 + 1]);
                out.add(new Successor(switchPc + off, state.copy()));
            }
        } else {
            out.add(new Successor(-1, state.copy()));
        }
    }

    private static boolean isIf(int op) {
        return op >= 0x32 && op <= 0x3d;
    }

    private static boolean isGoto(int op) {
        return op == 0x28 || op == 0x29 || op == 0x2a;
    }

    private static int gotoOffset(short[] units, int pc, int op) {
        if (op == 0x28) return (byte) ((units[pc] >>> 8) & 0xff);
        if (op == 0x29) return signed16(units[pc + 1]);
        return signed32(units[pc + 1], units[pc + 2]);
    }

    private static int signed16(short value) {
        return (short) (value & 0xffff);
    }

    private static int signed32(short low, short high) {
        return (low & 0xffff) | ((high & 0xffff) << 16);
    }

    private static boolean isReturnOrThrow(int op) {
        return op >= 0x0e && op <= 0x11 || op == 0x27;
    }

    private static ExceptionalInfo exceptionalBoundaries(Code code, short[] units) {
        ExceptionalInfo result = new ExceptionalInfo(units == null ? 0 : units.length);
        if (units == null) return result;
        Code.Try[] tries = code.getTries();
        if (tries == null || tries.length == 0) return result;
        Code.CatchHandler[] handlers = code.getCatchHandlers();
        if (handlers == null) { result.invalid = true; return result; }
        for (Code.Try t : tries) {
            int start = t.getStartAddress(), count = t.getInstructionCount();
            if (start < 0 || start >= units.length || count <= 0 || count > units.length - start
                    || t.getCatchHandlerIndex() < 0 || t.getCatchHandlerIndex() >= handlers.length) {
                result.invalid = true; return result;
            }
            int end = start + count;
            Code.CatchHandler handler = handlers[t.getCatchHandlerIndex()];
            List<Integer> targets = new ArrayList<>();
            if (handler.getAddresses() != null) for (int address : handler.getAddresses()) targets.add(address);
            if (handler.getCatchAllAddress() >= 0) targets.add(handler.getCatchAllAddress());
            if (targets.isEmpty()) { result.invalid = true; return result; }
            for (int address : targets) {
                if (address < 0 || address >= units.length) { result.invalid = true; return result; }
                result.handler[address] = true;
            }
            for (int pc = start; pc < end;) {
                result.inTry[pc] = true;
                result.targets.computeIfAbsent(pc, ignored -> new ArrayList<>()).addAll(targets);
                try {
                    int width = widthOf(units, pc, units[pc] & 0xff);
                    if (width <= 0 || width > end - pc) { result.invalid = true; return result; }
                    pc += width;
                } catch (RuntimeException ex) { result.invalid = true; return result; }
            }
        }
        return result;
    }

    private static final class ExceptionalInfo {
        final boolean[] inTry;
        final boolean[] handler;
        final Map<Integer, List<Integer>> targets = new HashMap<>();
        boolean invalid;

        ExceptionalInfo(int size) {
            inTry = new boolean[size];
            handler = new boolean[size];
        }
    }

    private static final class FlowState {
        final boolean[] knownNonNull;
        final int[] typeTestSource;
        boolean controlFlow;

        FlowState(int registersSize) {
            knownNonNull = new boolean[registersSize];
            typeTestSource = new int[registersSize];
            Arrays.fill(typeTestSource, -1);
        }

        void forgetTypeTest(int register) {
            for (int i = 0; i < typeTestSource.length; i++)
                if (i == register || typeTestSource[i] == register) typeTestSource[i] = -1;
        }

        FlowState copy() {
            FlowState copy = new FlowState(knownNonNull.length);
            System.arraycopy(knownNonNull, 0, copy.knownNonNull, 0, knownNonNull.length);
            System.arraycopy(typeTestSource, 0, copy.typeTestSource, 0, typeTestSource.length);
            copy.controlFlow = controlFlow;
            return copy;
        }
    }

    private static final class Successor {
        final int pc;
        final FlowState state;

        Successor(int pc, FlowState state) {
            this.pc = pc;
            this.state = state;
        }
    }

    private static void updateKnownNonNull(int op, int u0, short[] units, int pc,
                                           boolean[] known) {
        // 对象移动先读取源事实，避免同寄存器移动被误清空；check-cast 不改变值。
        if (op == 0x07) { copyKnown((u0 >>> 8) & 0x0f, (u0 >>> 12) & 0x0f, known); return; }
        if (op == 0x08) { copyKnown((u0 >>> 8) & 0xff, units[pc + 1] & 0xffff, known); return; }
        if (op == 0x09) { copyKnown(units[pc + 1] & 0xffff, units[pc + 2] & 0xffff, known); return; }
        if (op == 0x1f) return;

        // 复用 dexlib2 的写寄存器标记，统一清除 wide 的两格及 lit8 的完整 8 位目标。
        Opcode opcode = OPCODES.getOpcodeByValue(op);
        if (opcode == null || !opcode.setsRegister()) return;
        int destination = destination(opcode, u0, units, pc);
        clearKnown(destination, known);
        if (opcode.setsWideRegister()) clearKnown(destination + 1, known);
        if (op == 0x0d || op == 0x1a || op == 0x1b || op == 0x1c || op == 0x22 || op == 0x23) {
            setKnown(destination, known, true);
        }
    }

    private static int destination(Opcode opcode, int u0, short[] units, int pc) {
        return switch (opcode.format) {
            case Format11n, Format12x, Format22c, Format22cs, Format22s -> (u0 >>> 8) & 0x0f;
            case Format32x -> units[pc + 1] & 0xffff;
            default -> (u0 >>> 8) & 0xff;
        };
    }

    private static void copyKnown(int dst, int src, boolean[] known) {
        if (dst >= 0 && dst < known.length) {
            known[dst] = src >= 0 && src < known.length && known[src];
        }
    }

    private static void setKnown(int reg, boolean[] known, boolean value) {
        if (reg >= 0 && reg < known.length) known[reg] = value;
    }

    private static void clearKnown(int reg, boolean[] known) {
        setKnown(reg, known, false);
    }

    private static boolean isInvoke35(int op) {
        return op == 0x6e || op == 0x6f || op == 0x70 || op == 0x72;
    }

    private static boolean isInvoke3r(int op) {
        return op == 0x74 || op == 0x75 || op == 0x76 || op == 0x78;
    }

    private static boolean isControlFlow(int op) {
        return (op >= 0x28 && op <= 0x3d) || op == 0x2b || op == 0x2c;
    }

    private static int widthOf(short[] units, int pc, int op) {
        int ident = units[pc] & 0xffff;
        if (op == 0 && (ident == 0x0100 || ident == 0x0200 || ident == 0x0300)) {
            if (ident == 0x0100) {
                int size = units[pc + 1] & 0xffff;
                return 4 + size * 2;
            }
            if (ident == 0x0200) {
                int size = units[pc + 1] & 0xffff;
                return 2 + size * 4;
            }
            int elemWidth = units[pc + 1] & 0xffff;
            long size = (units[pc + 2] & 0xffffL) | ((units[pc + 3] & 0xffffL) << 16);
            long dataUnits = (size * elemWidth + 1L) / 2L;
            if (elemWidth <= 0 || dataUnits > Integer.MAX_VALUE - 4L) {
                throw new IllegalArgumentException("bad payload");
            }
            return 4 + (int) dataUnits;
        }
        switch (op) {
            case 0x03: case 0x06: case 0x09: case 0x14: case 0x17: case 0x1b:
            case 0x24: case 0x25: case 0x26: case 0x2a: case 0x2b: case 0x2c:
            case 0x6e: case 0x6f: case 0x70: case 0x71: case 0x72:
            case 0x74: case 0x75: case 0x76: case 0x77: case 0x78:
                return 3;
            case 0x18: return 5;
            case 0xfa: case 0xfb: return 4;
            case 0x01: case 0x04: case 0x07: case 0x0a: case 0x0b: case 0x0c:
            case 0x0d: case 0x0e: case 0x0f: case 0x10: case 0x11: case 0x12:
            case 0x1d: case 0x1e: case 0x21: case 0x27: case 0x28:
            case 0x7b: case 0x7c: case 0x7d: case 0x7e: case 0x7f: case 0x80:
            case 0x81: case 0x82: case 0x83: case 0x84: case 0x85: case 0x86:
            case 0x87: case 0x88: case 0x89: case 0x8a: case 0x8b: case 0x8c:
            case 0x8d: case 0x8e: case 0x8f:
                return 1;
            default:
                if (op >= 0xb0 && op <= 0xcf) return 1;
                if (op <= 0x00) return 1;
                return 2;
        }
    }
}
