#pragma once

#include <cstddef>
#include <vector>

namespace protector {

// volatile 写入不能作为死存储删除；不依赖高版本 Android 的 libc 扩展。
inline void secure_wipe(void* data, size_t size) noexcept {
    auto* p = static_cast<volatile unsigned char*>(data);
    while (size-- != 0) *p++ = 0;
}

template <typename T>
inline void wipe_vector(std::vector<T>& value) noexcept {
    secure_wipe(value.data(), value.size() * sizeof(T));
    std::vector<T>().swap(value);
}

} // namespace protector
