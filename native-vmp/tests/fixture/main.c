#include "mocika_native_vmp.h"

#include <stdint.h>
#include <stdio.h>

MOCIKA_VMP static uint32_t protected_score(uint32_t value, uint32_t rounds) {
    uint32_t result = value;
    for (uint32_t i = 0; i < rounds; ++i) {
        result = (result * 13 + i) ^ (result >> 3);
    }
    return result;
}

static uint32_t reference_score(uint32_t value, uint32_t rounds) {
    uint32_t result = value;
    for (uint32_t i = 0; i < rounds; ++i) {
        result = (result * 13 + i) ^ (result >> 3);
    }
    return result;
}

MOCIKA_VMP int fixed_value(void) { return 73; }
int call_fixed(void) { return fixed_value(); }

int main(void) {
    if (call_fixed() != 73) return 2;
    for (int32_t value = 1; value < 40; ++value) {
        for (int32_t rounds = 0; rounds < 12; ++rounds) {
            if (protected_score(value, rounds) != reference_score(value, rounds)) {
                return 1;
            }
        }
    }
    puts("Mocika Native VMP self-test passed");
    return 0;
}
