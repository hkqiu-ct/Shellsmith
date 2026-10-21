package dev.mocika.shield.loader;

import android.content.Context;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import java.io.File;
import java.io.RandomAccessFile;
import java.nio.channels.FileLock;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.spec.ECGenParameterSpec;
import java.util.Base64;

/** 无 Google 依赖；证明设备持有密钥，是否授权必须由客户服务端决定。 */
final class ByosProof {
    static final String MODE = "device_approval";
    static final int MIN_API = 26;

    static AutoCloseable startupContext(Context ctx) throws Exception {
        if (android.os.Build.VERSION.SDK_INT >= 31) return null;
        // API 26～30 的 AndroidKeyStore 在构造时读取全局 Application，
        // 此时框架尚未写入。仅在取钥期间借用已 attach 的壳，结束或超时后恢复。
        // ponytail: 旧系统依赖框架字段；字段不可访问时失败关闭，不退回可导出的软件密钥。
        Class<?> type = Class.forName("android.app.ActivityThread");
        Object thread = type.getMethod("currentActivityThread").invoke(null);
        java.lang.reflect.Field field = type.getDeclaredField("mInitialApplication");
        field.setAccessible(true);
        if (field.get(thread) != null) return null;
        if (!(ctx instanceof android.app.Application)) throw new SecurityException("K05");
        field.set(thread, ctx);
        return () -> { if (field.get(thread) == ctx) field.set(thread, null); };
    }

    static synchronized KeyPair deviceKey(Context ctx, String endpoint, String certificate) throws Exception {
        // 同一服务、包名、证书跨构建复用；清数据/卸载或密钥失效后须重新批准，不能自动放行。
        String scope = endpoint + "\n" + ctx.getPackageName() + "\n" + certificate;
        String alias = "shellsmith.byos.device.v1." + Base64.getUrlEncoder().withoutPadding().encodeToString(
                MessageDigest.getInstance("SHA-256").digest(scope.getBytes(StandardCharsets.UTF_8)));
        // 防止多个进程首次启动同时创建同名密钥，相互覆盖已提交批准的公钥。
        // ponytail: 进程内按类串行；多服务高并发时可改成按别名的进程内锁。
        try (RandomAccessFile file = new RandomAccessFile(new File(ctx.getNoBackupFilesDir(), alias + ".lock"), "rw");
                FileLock lock = file.getChannel().lock()) {
            KeyStore store = KeyStore.getInstance("AndroidKeyStore"); store.load(null);
            if (!store.containsAlias(alias)) {
                KeyPairGenerator generator = KeyPairGenerator.getInstance("EC", "AndroidKeyStore");
                generator.initialize(new KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN)
                        .setAlgorithmParameterSpec(new ECGenParameterSpec("secp256r1"))
                        .setDigests(KeyProperties.DIGEST_SHA256).build());
                generator.generateKeyPair();
            }
            return new KeyPair(store.getCertificate(alias).getPublicKey(), (PrivateKey) store.getKey(alias, null));
        }
    }

    static String integrityToken(Context ctx, String nonce) { throw new SecurityException("K02"); }
}
