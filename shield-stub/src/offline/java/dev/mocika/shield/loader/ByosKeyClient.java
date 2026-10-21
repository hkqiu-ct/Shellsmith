package dev.mocika.shield.loader;

import android.content.Context;

/** 默认离线资源不携带 Play Integrity，也不接受远程密钥格式。 */
final class ByosKeyClient {
    static byte[] fetch(Context ctx, String endpoint, String token, String certificate) {
        throw new SecurityException("K00");
    }
}
