#include "mocika_native_vmp.h"

#include <limits.h>
#include <errno.h>
#include <math.h>

#ifdef __FAST_MATH__
#error "Native VMP runtime requires IEEE floating-point semantics"
#endif
#include <string.h>

enum {
    MOCIKA_VMP_MAX_REGISTERS = 512,
    OP_BLOCK = 1,
    OP_PHI = 2,
    OP_ADD = 3,
    OP_SUB = 4,
    OP_MUL = 5,
    OP_UDIV = 6,
    OP_SDIV = 7,
    OP_UREM = 8,
    OP_SREM = 9,
    OP_AND = 10,
    OP_OR = 11,
    OP_XOR = 12,
    OP_SHL = 13,
    OP_LSHR = 14,
    OP_ASHR = 15,
    OP_ICMP = 16,
    OP_SELECT = 17,
    OP_TRUNC = 18,
    OP_ZEXT = 19,
    OP_SEXT = 20,
    OP_BR = 21,
    OP_CBR = 22,
    OP_RET = 23,
    OP_FADD = 24, OP_FSUB = 25, OP_FMUL = 26, OP_FDIV = 27, OP_FREM = 28,
    OP_FNEG = 29, OP_FCMP = 30, OP_FPTRUNC = 31, OP_FPEXT = 32,
    OP_FPTOUI = 33, OP_FPTOSI = 34, OP_UITOFP = 35, OP_SITOFP = 36,
    OP_BITCAST = 37, OP_FMA = 38,
};

typedef struct {
    const uint8_t *program;
    uint32_t size;
    uint32_t pc;
    int failed;
    uint64_t seed;
    uint8_t version;
} Reader;

static uint8_t read_u8(Reader *reader) {
    if (reader->pc >= reader->size) {
        reader->failed = 1;
        return 0;
    }
    const uint32_t position = reader->pc++;
    uint8_t value = reader->program[position];
    if (reader->version == 2 && position >= 18) {
        uint64_t x = reader->seed + position * UINT64_C(0x9e3779b97f4a7c15);
        x = (x ^ (x >> 30)) * UINT64_C(0xbf58476d1ce4e5b9);
        x = (x ^ (x >> 27)) * UINT64_C(0x94d049bb133111eb);
        value ^= (uint8_t)(x ^ (x >> 31));
    }
    return value;
}

static uint16_t read_u16(Reader *reader) {
    uint16_t value = read_u8(reader);
    value |= (uint16_t)read_u8(reader) << 8;
    return value;
}

static uint32_t read_u32(Reader *reader) {
    uint32_t value = read_u16(reader);
    value |= (uint32_t)read_u16(reader) << 16;
    return value;
}

static uint64_t read_u64(Reader *reader) {
    uint64_t value = read_u32(reader);
    value |= (uint64_t)read_u32(reader) << 32;
    return value;
}

static uint64_t width_mask(uint8_t width) {
    return width == 64 ? UINT64_MAX : ((UINT64_C(1) << width) - 1);
}

static uint64_t truncate_width(uint64_t value, uint8_t width) {
    return value & width_mask(width);
}

static int64_t signed_width(uint64_t value, uint8_t width) {
    value = truncate_width(value, width);
    if (width == 64) {
        return (int64_t)value;
    }
    const uint64_t sign = UINT64_C(1) << (width - 1);
    return (int64_t)((value ^ sign) - sign);
}

static uint64_t read_value(Reader *reader,
                           const uint64_t *registers,
                           uint16_t register_count) {
    const uint8_t kind = read_u8(reader);
    if (kind == 1) {
        return read_u64(reader);
    }
    if (kind != 0) {
        reader->failed = 1;
        return 0;
    }
    const uint16_t index = read_u16(reader);
    if (index >= register_count) {
        reader->failed = 1;
        return 0;
    }
    return registers[index];
}

static int valid_width(uint8_t width) {
    return width > 0 && width <= 64;
}

static float as_float(uint64_t bits) {
    uint32_t narrow = (uint32_t)bits; float value;
    memcpy(&value, &narrow, sizeof(value)); return value;
}
static double as_double(uint64_t bits) {
    double value; memcpy(&value, &bits, sizeof(value)); return value;
}
static uint64_t float_bits(float value) {
    uint32_t bits; memcpy(&bits, &value, sizeof(bits)); return bits;
}
static uint64_t double_bits(double value) {
    uint64_t bits; memcpy(&bits, &value, sizeof(bits)); return bits;
}
static int fp_width(uint8_t width) { return width == 32 || width == 64; }

static void wipe_registers(uint64_t *registers, uint16_t count) {
    volatile uint64_t *memory = registers;
    while (count--) *memory++ = 0;
}

uint64_t mocika_vmp_exec_i64(const uint8_t *program,
                             uint32_t program_size,
                             const uint64_t *arguments,
                             uint32_t argument_count,
                             uint32_t *ok) {
    uint64_t registers[MOCIKA_VMP_MAX_REGISTERS] = {0};
    uint64_t previous_registers[MOCIKA_VMP_MAX_REGISTERS] = {0};
    uint16_t previous_block = UINT16_MAX;
    uint16_t current_block = UINT16_MAX;
    Reader reader = {program, program_size, 0, 0, 0, 0};
    uint64_t returned = 0;
    const int saved_errno = errno;

    if (ok != NULL) {
        *ok = 0;
    }
    if (program == NULL || arguments == NULL || ok == NULL || program_size < 10 ||
        read_u8(&reader) != 'M' || read_u8(&reader) != 'V' ||
        read_u8(&reader) != 'M' || read_u8(&reader) != 'P') {
        return 0;
    }

    reader.version = read_u8(&reader);
    if (reader.version != 1 && reader.version != 2) return 0;
    const uint8_t opcode_key = read_u8(&reader);
    const uint16_t register_count = read_u16(&reader);
    const uint16_t expected_arguments = read_u16(&reader);
    if (reader.version == 2) reader.seed = read_u64(&reader);
    const uint32_t body_start = reader.pc;
    if (reader.failed || opcode_key == 0 || register_count == 0 ||
        register_count > MOCIKA_VMP_MAX_REGISTERS ||
        expected_arguments != argument_count || argument_count > register_count) {
        return 0;
    }
    for (uint32_t i = 0; i < argument_count; ++i) {
        registers[i] = arguments[i];
    }

    while (!reader.failed && reader.pc < reader.size) {
        const uint8_t opcode = read_u8(&reader) ^ opcode_key;
        if (opcode == OP_BLOCK) {
            current_block = read_u16(&reader);
            continue;
        }
        if (current_block == UINT16_MAX) {
            reader.failed = 1;
            break;
        }
        if (opcode == OP_PHI) {
            const uint16_t destination = read_u16(&reader);
            const uint8_t width = read_u8(&reader);
            const uint16_t count = read_u16(&reader);
            uint64_t selected = 0;
            int matched = 0;
            if (destination >= register_count || !valid_width(width) || count == 0) {
                reader.failed = 1;
                break;
            }
            for (uint16_t i = 0; i < count; ++i) {
                const uint16_t source_block = read_u16(&reader);
                const uint64_t value = read_value(
                    &reader, previous_registers, register_count);
                if (source_block == previous_block) {
                    selected = value;
                    matched = 1;
                }
            }
            if (!matched) {
                reader.failed = 1;
                break;
            }
            registers[destination] = truncate_width(selected, width);
            continue;
        }
        if (opcode >= OP_ADD && opcode <= OP_ASHR) {
            const uint16_t destination = read_u16(&reader);
            const uint8_t width = read_u8(&reader);
            const uint64_t left = read_value(&reader, registers, register_count);
            const uint64_t right = read_value(&reader, registers, register_count);
            uint64_t result = 0;
            if (destination >= register_count || !valid_width(width)) {
                reader.failed = 1;
                break;
            }
            const uint64_t lhs = truncate_width(left, width);
            const uint64_t rhs = truncate_width(right, width);
            switch (opcode) {
                case OP_ADD: result = lhs + rhs; break;
                case OP_SUB: result = lhs - rhs; break;
                case OP_MUL: result = lhs * rhs; break;
                case OP_UDIV:
                    if (rhs == 0) reader.failed = 1; else result = lhs / rhs;
                    break;
                case OP_SDIV: {
                    const int64_t a = signed_width(lhs, width);
                    const int64_t b = signed_width(rhs, width);
                    if (b == 0 || (width == 64 && a == INT64_MIN && b == -1)) {
                        reader.failed = 1;
                    } else {
                        result = (uint64_t)(a / b);
                    }
                    break;
                }
                case OP_UREM:
                    if (rhs == 0) reader.failed = 1; else result = lhs % rhs;
                    break;
                case OP_SREM: {
                    const int64_t a = signed_width(lhs, width);
                    const int64_t b = signed_width(rhs, width);
                    if (b == 0 || (width == 64 && a == INT64_MIN && b == -1)) {
                        reader.failed = 1;
                    } else {
                        result = (uint64_t)(a % b);
                    }
                    break;
                }
                case OP_AND: result = lhs & rhs; break;
                case OP_OR: result = lhs | rhs; break;
                case OP_XOR: result = lhs ^ rhs; break;
                case OP_SHL:
                    if (rhs >= width) reader.failed = 1; else result = lhs << rhs;
                    break;
                case OP_LSHR:
                    if (rhs >= width) reader.failed = 1; else result = lhs >> rhs;
                    break;
                case OP_ASHR:
                    if (rhs >= width) reader.failed = 1;
                    else result = (uint64_t)(signed_width(lhs, width) >> rhs);
                    break;
            }
            if (reader.failed) break;
            registers[destination] = truncate_width(result, width);
            continue;
        }
        if (opcode >= OP_FADD && opcode <= OP_FNEG) {
            const uint16_t destination = read_u16(&reader);
            const uint8_t width = read_u8(&reader);
            const uint64_t left = read_value(&reader, registers, register_count);
            const uint64_t right = opcode == OP_FNEG ? 0 : read_value(&reader, registers, register_count);
            if (reader.failed || destination >= register_count || !fp_width(width)) { reader.failed = 1; break; }
            if (opcode == OP_FNEG) {
                registers[destination] = truncate_width(left ^ (UINT64_C(1) << (width - 1)), width);
            } else if (width == 32) {
                float a = as_float(left), b = as_float(right), result;
                switch (opcode) {
                    case OP_FADD: result = a + b; break;
                    case OP_FSUB: result = a - b; break;
                    case OP_FMUL: result = a * b; break;
                    case OP_FDIV: result = a / b; break;
                    default: result = fmodf(a, b); break;
                }
                registers[destination] = float_bits(result);
            } else {
                double a = as_double(left), b = as_double(right), result;
                switch (opcode) {
                    case OP_FADD: result = a + b; break;
                    case OP_FSUB: result = a - b; break;
                    case OP_FMUL: result = a * b; break;
                    case OP_FDIV: result = a / b; break;
                    default: result = fmod(a, b); break;
                }
                registers[destination] = double_bits(result);
            }
            continue;
        }
        if (opcode == OP_FMA) {
            const uint16_t destination = read_u16(&reader);
            const uint8_t width = read_u8(&reader);
            const uint64_t a = read_value(&reader, registers, register_count);
            const uint64_t b = read_value(&reader, registers, register_count);
            const uint64_t c = read_value(&reader, registers, register_count);
            if (reader.failed || destination >= register_count || !fp_width(width)) { reader.failed = 1; break; }
            registers[destination] = width == 32 ? float_bits(fmaf(as_float(a), as_float(b), as_float(c)))
                                                : double_bits(fma(as_double(a), as_double(b), as_double(c)));
            continue;
        }
        if (opcode == OP_FCMP) {
            const uint16_t destination = read_u16(&reader);
            const uint8_t width = read_u8(&reader), predicate = read_u8(&reader);
            const uint64_t left = read_value(&reader, registers, register_count);
            const uint64_t right = read_value(&reader, registers, register_count);
            if (reader.failed || destination >= register_count || !fp_width(width) || predicate > 15) { reader.failed = 1; break; }
            double a = width == 32 ? (double)as_float(left) : as_double(left);
            double b = width == 32 ? (double)as_float(right) : as_double(right);
            const int unordered = isnan(a) || isnan(b);
            int result = 0;
            switch (predicate & 7) {
                case 0: result = 0; break;
                case 1: result = a == b; break;
                case 2: result = a > b; break;
                case 3: result = a >= b; break;
                case 4: result = a < b; break;
                case 5: result = a <= b; break;
                case 6: result = a != b; break;
                case 7: result = 1; break;
            }
            registers[destination] = (uint64_t)(predicate < 8 ? (!unordered && result) : (unordered || result));
            continue;
        }
        if (opcode >= OP_FPTRUNC && opcode <= OP_BITCAST) {
            const uint16_t destination = read_u16(&reader);
            const uint8_t source_width = read_u8(&reader), destination_width = read_u8(&reader);
            const uint64_t source = read_value(&reader, registers, register_count);
            if (reader.failed || destination >= register_count || !valid_width(source_width) || !valid_width(destination_width)) { reader.failed = 1; break; }
            uint64_t result = 0;
            if (opcode == OP_BITCAST) {
                if (source_width != destination_width) { reader.failed = 1; break; }
                result = source;
            } else if (opcode == OP_FPTRUNC || opcode == OP_FPEXT) {
                if (source_width != (opcode == OP_FPTRUNC ? 64 : 32) || destination_width != (opcode == OP_FPTRUNC ? 32 : 64)) { reader.failed = 1; break; }
                result = opcode == OP_FPTRUNC ? float_bits((float)as_double(source)) : double_bits((double)as_float(source));
            } else if (opcode == OP_FPTOUI || opcode == OP_FPTOSI) {
                if (!fp_width(source_width)) { reader.failed = 1; break; }
                double value = trunc(source_width == 32 ? (double)as_float(source) : as_double(source));
                const double limit = ldexp(1.0, destination_width - (opcode == OP_FPTOSI));
                // LLVM 对越界转换定义为 poison；运行时拒绝，避免 C 浮点转整数的未定义行为。
                if (!isfinite(value) || value < (opcode == OP_FPTOSI ? -limit : 0.0) || value >= limit) { reader.failed = 1; break; }
                result = opcode == OP_FPTOSI ? (uint64_t)(int64_t)value : (uint64_t)value;
            } else {
                if (!fp_width(destination_width)) { reader.failed = 1; break; }
                // 直接按目标精度转换，避免 uint64 -> double -> float 的二次舍入。
                if (opcode == OP_SITOFP) result = destination_width == 32
                    ? float_bits((float)signed_width(source, source_width)) : double_bits((double)signed_width(source, source_width));
                else result = destination_width == 32
                    ? float_bits((float)truncate_width(source, source_width)) : double_bits((double)truncate_width(source, source_width));
            }
            registers[destination] = truncate_width(result, destination_width);
            continue;
        }
        if (opcode == OP_ICMP) {
            const uint16_t destination = read_u16(&reader);
            const uint8_t width = read_u8(&reader);
            const uint8_t predicate = read_u8(&reader);
            const uint64_t left = read_value(&reader, registers, register_count);
            const uint64_t right = read_value(&reader, registers, register_count);
            if (destination >= register_count || !valid_width(width)) {
                reader.failed = 1;
                break;
            }
            const uint64_t lhs = truncate_width(left, width);
            const uint64_t rhs = truncate_width(right, width);
            int result = 0;
            switch (predicate) {
                case 0: result = lhs == rhs; break;
                case 1: result = lhs != rhs; break;
                case 2: result = lhs > rhs; break;
                case 3: result = lhs >= rhs; break;
                case 4: result = lhs < rhs; break;
                case 5: result = lhs <= rhs; break;
                case 6: result = signed_width(lhs, width) > signed_width(rhs, width); break;
                case 7: result = signed_width(lhs, width) >= signed_width(rhs, width); break;
                case 8: result = signed_width(lhs, width) < signed_width(rhs, width); break;
                case 9: result = signed_width(lhs, width) <= signed_width(rhs, width); break;
                default: reader.failed = 1; break;
            }
            if (reader.failed) break;
            registers[destination] = (uint64_t)result;
            continue;
        }
        if (opcode == OP_SELECT) {
            const uint16_t destination = read_u16(&reader);
            const uint8_t width = read_u8(&reader);
            const uint64_t condition = read_value(&reader, registers, register_count);
            const uint64_t when_true = read_value(&reader, registers, register_count);
            const uint64_t when_false = read_value(&reader, registers, register_count);
            if (destination >= register_count || !valid_width(width)) {
                reader.failed = 1;
                break;
            }
            registers[destination] = truncate_width(
                condition != 0 ? when_true : when_false, width);
            continue;
        }
        if (opcode >= OP_TRUNC && opcode <= OP_SEXT) {
            const uint16_t destination = read_u16(&reader);
            const uint8_t source_width = read_u8(&reader);
            const uint8_t destination_width = read_u8(&reader);
            const uint64_t source = read_value(&reader, registers, register_count);
            if (destination >= register_count || !valid_width(source_width) ||
                !valid_width(destination_width)) {
                reader.failed = 1;
                break;
            }
            if (opcode == OP_SEXT) {
                registers[destination] = truncate_width(
                    (uint64_t)signed_width(source, source_width), destination_width);
            } else {
                registers[destination] = truncate_width(source, destination_width);
            }
            continue;
        }
        if (opcode == OP_BR || opcode == OP_CBR) {
            uint64_t condition = 1;
            uint32_t when_true;
            uint32_t when_false = 0;
            if (opcode == OP_CBR) {
                condition = read_value(&reader, registers, register_count);
            }
            when_true = read_u32(&reader);
            if (opcode == OP_CBR) {
                when_false = read_u32(&reader);
            }
            const uint32_t target = condition != 0 ? when_true : when_false;
            if (target < body_start || target >= reader.size || reader.failed) {
                reader.failed = 1;
                break;
            }
            memcpy(previous_registers, registers,
                   (size_t)register_count * sizeof(registers[0]));
            previous_block = current_block;
            reader.pc = target;
            continue;
        }
        if (opcode == OP_RET) {
            const uint8_t width = read_u8(&reader);
            const uint64_t value = read_value(&reader, registers, register_count);
            if (!valid_width(width) || reader.failed) {
                break;
            }
            *ok = 1;
            returned = truncate_width(value, width);
            break;
        }
        reader.failed = 1;
    }
    wipe_registers(registers, register_count);
    wipe_registers(previous_registers, register_count);
    // LLVM 标量指令（包括 fma/fmuladd）不写 errno，libm 回退不能改变调用者状态。
    errno = saved_errno;
    return returned;
}

