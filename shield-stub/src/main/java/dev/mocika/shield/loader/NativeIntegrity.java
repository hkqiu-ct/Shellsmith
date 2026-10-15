package dev.mocika.shield.loader;

import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;
import android.util.Log;

import dev.mocika.shield.stub.BuildConfig;

import java.io.FileInputStream;
import java.io.DataInputStream;

import dalvik.system.BaseDexClassLoader;
import java.io.InputStream;
import java.security.MessageDigest;
import java.util.Locale;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

/** 沿壳类加载器的实际解析路径校验文件摘要；不验证进程内代码是否被修改。 */
final class NativeIntegrity {

    private static final String TAG = "NativeIntegrity";
    private static final String FIELD = "dev.mocika.shield.NATIVE_INTEGRITY";
    private NativeIntegrity() {
    }

    static void verify(Context context) throws Exception {
        if (!BuildConfig.NATIVE_SELF_CHECK) return;
        ApplicationInfo info = context.getPackageManager().getApplicationInfo(
                context.getPackageName(), PackageManager.GET_META_DATA);
        String expected = info.metaData == null ? null : info.metaData.getString(FIELD);
        ClassLoader loader = Ld.class.getClassLoader();
        if (!(loader instanceof BaseDexClassLoader)) throw new SecurityException("N71");
        // 与 Ld.loadLibrary 共用任务别名占位符；核心会改写所有匹配字符串。
        String path = ((BaseDexClassLoader) loader).findLibrary("mocikanativeslot");
        verifyResolvedLibrary(path, expected);
        if (BuildConfig.DEBUG_LOGS) Log.d(TAG, "native integrity ok");
    }

    static void verifyResolvedLibrary(String path, String expected) throws Exception {
        if (path == null || path.isEmpty()) throw new SecurityException("N71");
        int separator = path.indexOf("!/");
        if (separator < 0) {
            try (InputStream input = new FileInputStream(path)) { verifyStream(input, expected); }
        } else {
            // 同样支持库实际位于 ABI split APK 的情况，不猜设备首选 ABI 或 base.apk。
            String entryName = path.substring(separator + 2);
            try (ZipFile zip = new ZipFile(path.substring(0, separator))) {
                int count = 0;
                java.util.Enumeration<? extends ZipEntry> entries = zip.entries();
                while (entries.hasMoreElements()) if (entries.nextElement().getName().equals(entryName)) count++;
                ZipEntry entry = zip.getEntry(entryName);
                if (count != 1 || entry == null || entry.isDirectory()) throw new SecurityException("N71");
                try (InputStream input = zip.getInputStream(entry)) { verifyStream(input, expected); }
            }
        }
    }

    static String selectAbiDigest(String raw, String abi) {
        if (raw == null || abi == null) throw new SecurityException("N70");
        String result = null;
        for (String part : raw.split(",")) {
            int colon = part.indexOf(':');
            if (colon <= 0 || !part.substring(0, colon).equals(abi)) continue;
            String digest = part.substring(colon + 1);
            if (result != null || !digest.matches("[0-9a-fA-F]{64}")) throw new SecurityException("N70");
            result = digest;
        }
        if (result == null) throw new SecurityException("N70");
        return result;
    }

    static void verifyStream(InputStream input, String expected) throws Exception {
        byte[] header = new byte[20];
        new DataInputStream(input).readFully(header);
        if (header[0] != 0x7f || header[1] != 'E' || header[2] != 'L' || header[3] != 'F'
                || header[5] != 1 || header[6] != 1 || header[16] != 3 || header[17] != 0) {
            throw new SecurityException("N73");
        }
        int machine = (header[18] & 255) | ((header[19] & 255) << 8);
        String abi;
        if (machine == 183 && header[4] == 2) abi = "arm64-v8a";
        else if (machine == 40 && header[4] == 1) abi = "armeabi-v7a";
        else if (machine == 62 && header[4] == 2) abi = "x86_64";
        else if (machine == 3 && header[4] == 1) abi = "x86";
        else throw new SecurityException("N73");
        String digest = selectAbiDigest(expected, abi);
        MessageDigest sha = MessageDigest.getInstance("SHA-256");
        sha.update(header);
        byte[] buffer = new byte[8192];
        int read;
        while ((read = input.read(buffer)) != -1) sha.update(buffer, 0, read);
        if (!digest.equalsIgnoreCase(toHex(sha.digest()))) throw new SecurityException("N72");
    }

    private static String toHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            sb.append(String.format(Locale.ROOT, "%02x", b & 0xFF));
        }
        return sb.toString();
    }
}
