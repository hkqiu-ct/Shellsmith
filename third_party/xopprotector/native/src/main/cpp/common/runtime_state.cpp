#include "common/runtime_state.h"
#include "common/secure_memory.h"
#include "vm/pvm2_format.h"

#include <cstring>

namespace protector {

CodeItem::CodeItem() = default;

CodeItem::~CodeItem() {
    wipe_plaintext();
}

void CodeItem::wipe_plaintext() noexcept {
    wipe_vector(vm_image);
    parsed_vm.reset();
}

RuntimeState& runtime_state() {
    static RuntimeState state;
    return state;
}

} // namespace protector
