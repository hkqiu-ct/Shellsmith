#include "crypto/aes.h"
#include "common/secure_memory.h"

#include <cstring>

namespace protector::crypto {

// Compact AES-128 (encrypt-only) + CTR + GCM. Public-domain style tables.

static const uint8_t kSbox[256] = {
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
};

static const uint8_t kRcon[11] = {
    0x00,0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36
};

static inline uint8_t xtime(uint8_t x) {
    return static_cast<uint8_t>((x << 1) ^ (((x >> 7) & 1) * 0x1b));
}

static void key_expansion(const uint8_t key[16], uint8_t rk[176]) {
    memcpy(rk, key, 16);
    for (int i = 4; i < 44; i++) {
        uint8_t t[4];
        memcpy(t, rk + (i - 1) * 4, 4);
        if (i % 4 == 0) {
            uint8_t tmp = t[0];
            t[0] = kSbox[t[1]] ^ kRcon[i / 4];
            t[1] = kSbox[t[2]];
            t[2] = kSbox[t[3]];
            t[3] = kSbox[tmp];
        }
        for (int j = 0; j < 4; j++) {
            rk[i * 4 + j] = rk[(i - 4) * 4 + j] ^ t[j];
        }
    }
}

static void add_round_key(uint8_t state[16], const uint8_t* rk) {
    for (int i = 0; i < 16; i++) state[i] ^= rk[i];
}

static void sub_bytes(uint8_t state[16]) {
    for (int i = 0; i < 16; i++) state[i] = kSbox[state[i]];
}

static void shift_rows(uint8_t state[16]) {
    uint8_t t;
    t = state[1]; state[1] = state[5]; state[5] = state[9]; state[9] = state[13]; state[13] = t;
    t = state[2]; state[2] = state[10]; state[10] = t; t = state[6]; state[6] = state[14]; state[14] = t;
    t = state[15]; state[15] = state[11]; state[11] = state[7]; state[7] = state[3]; state[3] = t;
}

static void mix_columns(uint8_t state[16]) {
    for (int i = 0; i < 4; i++) {
        uint8_t* c = state + i * 4;
        uint8_t a0 = c[0], a1 = c[1], a2 = c[2], a3 = c[3];
        c[0] = static_cast<uint8_t>(xtime(a0) ^ xtime(a1) ^ a1 ^ a2 ^ a3);
        c[1] = static_cast<uint8_t>(a0 ^ xtime(a1) ^ xtime(a2) ^ a2 ^ a3);
        c[2] = static_cast<uint8_t>(a0 ^ a1 ^ xtime(a2) ^ xtime(a3) ^ a3);
        c[3] = static_cast<uint8_t>(xtime(a0) ^ a0 ^ a1 ^ a2 ^ xtime(a3));
    }
}

static void encrypt_expanded_block(const uint8_t rk[176], const uint8_t in[16], uint8_t out[16]) {
    uint8_t state[16];
    memcpy(state, in, 16);
    add_round_key(state, rk);
    for (int round = 1; round <= 9; round++) {
        sub_bytes(state);
        shift_rows(state);
        mix_columns(state);
        add_round_key(state, rk + round * 16);
    }
    sub_bytes(state);
    shift_rows(state);
    add_round_key(state, rk + 160);
    memcpy(out, state, 16);
    secure_wipe(state, sizeof(state));
}

void aes128_encrypt_block(const uint8_t key[16], const uint8_t in[16], uint8_t out[16]) {
    uint8_t rk[176];
    key_expansion(key, rk);
    encrypt_expanded_block(rk, in, out);
    secure_wipe(rk, sizeof(rk));
}

static void ctr_inc(uint8_t counter[16]) {
    for (int i = 15; i >= 0; i--) {
        if (++counter[i] != 0) break;
    }
}

void aes128_ctr_crypt(const uint8_t key[16], const uint8_t* in, uint8_t* out, size_t len) {
    if (len == 0) return;
    uint8_t rk[176];
    key_expansion(key, rk);
    uint8_t counter[16] = {0};
    uint8_t keystream[16];
    size_t offset = 0;
    while (offset < len) {
        encrypt_expanded_block(rk, counter, keystream);
        size_t n = len - offset;
        if (n > 16) n = 16;
        for (size_t i = 0; i < n; i++) {
            out[offset + i] = in[offset + i] ^ keystream[i];
        }
        offset += n;
        ctr_inc(counter);
    }
    secure_wipe(rk, sizeof(rk));
    secure_wipe(keystream, sizeof(keystream));
}

// ── GCM (AES-128) ──────────────────────────────────────────────────

static void gf_mult(const uint8_t X[16], const uint8_t Y[16], uint8_t out[16]) {
    // 保留原 GHASH 位序和约简多项式，按两个 64 位字运算，减少每位的 16 字节搬移。
    // 显式大端读取支持未对齐输入，不依赖宿主字节序或 CPU 加密扩展。
    uint64_t x[2] = {}, v[2] = {}, z[2] = {};
    for (int i = 0; i < 16; i++) {
        x[i / 8] = (x[i / 8] << 8) | X[i];
        v[i / 8] = (v[i / 8] << 8) | Y[i];
    }
    for (int word = 0; word < 2; word++) {
        for (int bit = 63; bit >= 0; bit--) {
            uint64_t mask = uint64_t{0} - ((x[word] >> bit) & 1);
            z[0] ^= v[0] & mask;
            z[1] ^= v[1] & mask;
            uint64_t reduce = uint64_t{0} - (v[1] & 1);
            v[1] = (v[1] >> 1) | (v[0] << 63);
            v[0] = (v[0] >> 1) ^ (0xe100000000000000ULL & reduce);
        }
    }
    for (int i = 0; i < 16; i++) out[i] = static_cast<uint8_t>(z[i / 8] >> (56 - (i % 8) * 8));
    secure_wipe(x, sizeof(x));
    secure_wipe(v, sizeof(v));
    secure_wipe(z, sizeof(z));
}

static void ghash(const uint8_t H[16], const uint8_t* aad, size_t aad_len,
                  const uint8_t* ct, size_t ct_len, uint8_t out[16]) {
    uint8_t Y[16] = {0};
    auto absorb = [&](const uint8_t* block) {
        for (int i = 0; i < 16; i++) Y[i] ^= block[i];
        uint8_t tmp[16];
        gf_mult(Y, H, tmp);
        memcpy(Y, tmp, 16);
    };

    size_t full = aad_len / 16;
    for (size_t i = 0; i < full; i++) absorb(aad + i * 16);
    if (aad_len % 16) {
        uint8_t block[16] = {0};
        memcpy(block, aad + full * 16, aad_len % 16);
        absorb(block);
    }

    full = ct_len / 16;
    for (size_t i = 0; i < full; i++) absorb(ct + i * 16);
    if (ct_len % 16) {
        uint8_t block[16] = {0};
        memcpy(block, ct + full * 16, ct_len % 16);
        absorb(block);
    }

    uint8_t len_block[16] = {0};
    uint64_t aad_bits = static_cast<uint64_t>(aad_len) * 8;
    uint64_t ct_bits = static_cast<uint64_t>(ct_len) * 8;
    for (int i = 0; i < 8; i++) {
        len_block[i] = static_cast<uint8_t>((aad_bits >> (56 - 8 * i)) & 0xff);
        len_block[8 + i] = static_cast<uint8_t>((ct_bits >> (56 - 8 * i)) & 0xff);
    }
    absorb(len_block);
    memcpy(out, Y, 16);
}

static void gcm_ctr32_inc(uint8_t counter[16]) {
    // Increment last 32 bits (big-endian) — standard GCM J0 counter
    for (int i = 15; i >= 12; i--) {
        if (++counter[i] != 0) break;
    }
}

bool aes128_gcm_decrypt(const uint8_t key[16],
                        const uint8_t* enc, size_t enc_len,
                        uint8_t* plain, size_t plain_len) {
    if (key == nullptr || enc == nullptr || plain == nullptr) return false;
    if (enc_len < GCM_NONCE_LEN + GCM_TAG_LEN) return false;
    size_t ct_len = enc_len - GCM_NONCE_LEN - GCM_TAG_LEN;
    if (ct_len != plain_len) return false;

    const uint8_t* nonce = enc;
    const uint8_t* ct = enc + GCM_NONCE_LEN;
    const uint8_t* tag = enc + GCM_NONCE_LEN + ct_len;

    // 轮密钥只在本次调用内复用，认证失败和正常退出均清理，不进入全局缓存。
    uint8_t rk[176];
    key_expansion(key, rk);
    uint8_t H[16];
    uint8_t zero[16] = {0};
    encrypt_expanded_block(rk, zero, H);

    uint8_t J0[16] = {0};
    memcpy(J0, nonce, GCM_NONCE_LEN);
    J0[15] = 1;

    uint8_t S[16];
    ghash(H, nullptr, 0, ct, ct_len, S);

    uint8_t E0[16];
    encrypt_expanded_block(rk, J0, E0);
    uint8_t expected[16];
    for (int i = 0; i < 16; i++) expected[i] = S[i] ^ E0[i];

    int diff = 0;
    for (int i = 0; i < 16; i++) diff |= expected[i] ^ tag[i];
    secure_wipe(H, sizeof(H));
    secure_wipe(E0, sizeof(E0));
    secure_wipe(expected, sizeof(expected));
    if (diff != 0) {
        secure_wipe(rk, sizeof(rk));
        return false;
    }

    uint8_t counter[16];
    memcpy(counter, J0, 16);
    gcm_ctr32_inc(counter);

    size_t offset = 0;
    while (offset < ct_len) {
        uint8_t ks[16];
        encrypt_expanded_block(rk, counter, ks);
        size_t n = ct_len - offset;
        if (n > 16) n = 16;
        for (size_t i = 0; i < n; i++) {
            plain[offset + i] = ct[offset + i] ^ ks[i];
        }
        offset += n;
        gcm_ctr32_inc(counter);
        secure_wipe(ks, sizeof(ks));
    }
    secure_wipe(rk, sizeof(rk));
    return true;
}

bool aes128_gcm_encrypt(const uint8_t key[16],
                        const uint8_t nonce[12],
                        const uint8_t* plain, size_t plain_len,
                        uint8_t* out, size_t out_cap, size_t* out_len) {
    if (key == nullptr || nonce == nullptr || plain == nullptr || out == nullptr
            || out_len == nullptr) {
        return false;
    }
    if (out_cap < GCM_NONCE_LEN + GCM_TAG_LEN
            || plain_len > out_cap - GCM_NONCE_LEN - GCM_TAG_LEN) return false;
    size_t need = GCM_NONCE_LEN + plain_len + GCM_TAG_LEN;

    uint8_t rk[176];
    key_expansion(key, rk);
    uint8_t H[16];
    uint8_t zero[16] = {0};
    encrypt_expanded_block(rk, zero, H);

    uint8_t J0[16] = {0};
    memcpy(J0, nonce, GCM_NONCE_LEN);
    J0[15] = 1;

    memcpy(out, nonce, GCM_NONCE_LEN);
    uint8_t* ct = out + GCM_NONCE_LEN;

    uint8_t counter[16];
    memcpy(counter, J0, 16);
    gcm_ctr32_inc(counter);

    size_t offset = 0;
    while (offset < plain_len) {
        uint8_t ks[16];
        encrypt_expanded_block(rk, counter, ks);
        size_t n = plain_len - offset;
        if (n > 16) n = 16;
        for (size_t i = 0; i < n; i++) {
            ct[offset + i] = plain[offset + i] ^ ks[i];
        }
        offset += n;
        gcm_ctr32_inc(counter);
        secure_wipe(ks, sizeof(ks));
    }

    uint8_t S[16];
    ghash(H, nullptr, 0, ct, plain_len, S);

    uint8_t E0[16];
    encrypt_expanded_block(rk, J0, E0);
    uint8_t* tag = out + GCM_NONCE_LEN + plain_len;
    for (int i = 0; i < 16; i++) tag[i] = S[i] ^ E0[i];

    *out_len = need;
    secure_wipe(rk, sizeof(rk));
    secure_wipe(H, sizeof(H));
    secure_wipe(E0, sizeof(E0));
    return true;
}

// ── Self-test vs Java javax.crypto reference vectors (CryptoUtils) ──
// Keep AES self-test vectors out of .bitcode (packer encrypts that whole section).
#if defined(__APPLE__)
#define PROT_RODATA __attribute__((section("__TEXT,__prot"), used))
#else
#define PROT_RODATA __attribute__((section(".rodata.prot"), used))
#endif

bool aes_self_test() {
    uint8_t key[16];
    for (int i = 0; i < 16; i++) key[i] = static_cast<uint8_t>(i);
    uint8_t plain[32];
    for (int i = 0; i < 32; i++) plain[i] = static_cast<uint8_t>(0x10 + i);

    // Java AES/CTR/NoPadding + zero IV
    static const uint8_t kCtrExpected[32] PROT_RODATA = {
        0xd6,0xb0,0x29,0x24,0x93,0x9a,0x4d,0x95,0x77,0x56,0x9b,0x79,0xbd,0xd5,0xc6,0x66,
        0x53,0x67,0x31,0xb6,0xb1,0xe5,0x92,0x39,0x61,0x52,0x97,0xc8,0x49,0xd9,0x03,0x25
    };
    uint8_t ctr_out[32];
    aes128_ctr_crypt(key, plain, ctr_out, 32);
    if (memcmp(ctr_out, kCtrExpected, 32) != 0) return false;

    // Java AES/GCM: nonce 01..0c || ct||tag from Cipher.doFinal
    static const uint8_t kGcmPkg[12 + 32 + 16] PROT_RODATA = {
        0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,
        0x16,0x14,0x7a,0x35,0x27,0xe0,0x49,0xd2,0x20,0x45,0x17,0x5e,0xb1,0xc5,0x73,0x2a,
        0xe1,0xea,0xc5,0x7e,0xca,0x84,0xca,0x4b,0x75,0x8c,0x11,0x7c,0xc8,0xa4,0x42,0x73,
        0xac,0x53,0x4b,0x70,0x0f,0xc9,0x83,0x2e,0x58,0x96,0xe2,0xe9,0x17,0xde,0x56,0x0a
    };
    uint8_t gcm_plain[32];
    if (!aes128_gcm_decrypt(key, kGcmPkg, sizeof(kGcmPkg), gcm_plain, 32)) return false;
    if (memcmp(gcm_plain, plain, 32) != 0) return false;

    // Encrypt round-trip with the same nonce as the Java vector.
    uint8_t nonce[12];
    memcpy(nonce, kGcmPkg, 12);
    uint8_t enc_pkg[12 + 32 + 16];
    size_t enc_len = 0;
    if (!aes128_gcm_encrypt(key, nonce, plain, 32, enc_pkg, sizeof(enc_pkg), &enc_len)) {
        return false;
    }
    if (enc_len != sizeof(kGcmPkg) || memcmp(enc_pkg, kGcmPkg, sizeof(kGcmPkg)) != 0) {
        return false;
    }

    // NIST AES-128 ECB block
    static const uint8_t kNistKey[16] PROT_RODATA = {
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f
    };
    static const uint8_t kNistPt[16] PROT_RODATA = {
        0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff
    };
    static const uint8_t kNistCt[16] PROT_RODATA = {
        0x69,0xc4,0xe0,0xd8,0x6a,0x7b,0x04,0x30,0xd8,0xcd,0xb7,0x80,0x70,0xb4,0xc5,0x5a
    };
    uint8_t block[16];
    aes128_encrypt_block(kNistKey, kNistPt, block);
    if (memcmp(block, kNistCt, 16) != 0) return false;
    return true;
}

} // namespace protector::crypto
