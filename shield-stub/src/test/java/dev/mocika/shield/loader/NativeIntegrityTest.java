package dev.mocika.shield.loader;

import org.junit.Test;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.security.MessageDigest;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;
import static org.junit.Assert.*;

public class NativeIntegrityTest {
    private static byte[] elf(int machine, int bits) {
        byte[] bytes = new byte[128];
        bytes[0] = 0x7f; bytes[1] = 'E'; bytes[2] = 'L'; bytes[3] = 'F';
        bytes[4] = (byte) bits; bytes[5] = 1; bytes[6] = 1; bytes[16] = 3;
        bytes[18] = (byte) machine; bytes[19] = (byte) (machine >> 8);
        return bytes;
    }

    private static String digest(byte[] bytes) throws Exception {
        StringBuilder text = new StringBuilder();
        for (byte value : MessageDigest.getInstance("SHA-256").digest(bytes)) text.append(String.format("%02x", value & 255));
        return text.toString();
    }

    @Test public void 校验实际ELF架构而非设备首选ABI() throws Exception {
        byte[] arm = elf(40, 1);
        String raw = "arm64-v8a:" + digest(elf(183, 2)) + ",armeabi-v7a:" + digest(arm);
        NativeIntegrity.verifyStream(new ByteArrayInputStream(arm), raw);
        for (int[] arch : new int[][]{{183, 2}, {40, 1}, {62, 2}, {3, 1}}) {
            byte[] bytes = elf(arch[0], arch[1]);
            String abi = arch[0] == 183 ? "arm64-v8a" : arch[0] == 40 ? "armeabi-v7a" : arch[0] == 62 ? "x86_64" : "x86";
            NativeIntegrity.verifyStream(new ByteArrayInputStream(bytes), abi + ":" + digest(bytes));
        }
        arm[90] = 1;
        try { NativeIntegrity.verifyStream(new ByteArrayInputStream(arm), raw); fail(); }
        catch (SecurityException expected) { assertEquals("N72", expected.getMessage()); }
    }

    @Test public void 拒绝截断读取异常与错误摘要字段() throws Exception {
        byte[] bytes = elf(183, 2);
        for (String raw : new String[]{null, "", "arm64-v8a:aabb", "x86:" + digest(bytes),
                "arm64-v8a:" + digest(bytes) + ",arm64-v8a:" + digest(bytes)}) {
            try { NativeIntegrity.verifyStream(new ByteArrayInputStream(bytes), raw); fail(); }
            catch (SecurityException expected) { assertEquals("N70", expected.getMessage()); }
        }
        try { NativeIntegrity.verifyStream(new ByteArrayInputStream(new byte[19]), null); fail(); }
        catch (IOException expected) { }
        try {
            NativeIntegrity.verifyStream(new InputStream() {
                public int read() throws IOException { throw new IOException("读取失败"); }
            }, "arm64-v8a:" + digest(bytes));
            fail();
        } catch (IOException expected) { assertEquals("读取失败", expected.getMessage()); }
        bytes[5] = 2;
        try { NativeIntegrity.verifyStream(new ByteArrayInputStream(bytes), "arm64-v8a:" + digest(bytes)); fail(); }
        catch (SecurityException expected) { assertEquals("N73", expected.getMessage()); }
    }

    @Test public void 精确校验解压文件及ABI拆分包中的已解析路径() throws Exception {
        File directory = Files.createTempDirectory("native-integrity").toFile();
        File so = new File(directory, "libactual.so");
        File unrelated = new File(directory, "libmoduleapisupport.so");
        File split = new File(directory, "split_config.arm64_v8a.apk");
        byte[] bytes = elf(183, 2);
        String raw = "arm64-v8a:" + digest(bytes);
        try {
            Files.write(so.toPath(), bytes);
            Files.write(unrelated.toPath(), new byte[128]);
            NativeIntegrity.verifyResolvedLibrary(so.getPath(), raw);
            try (ZipOutputStream zip = new ZipOutputStream(Files.newOutputStream(split.toPath()))) {
                zip.putNextEntry(new ZipEntry("lib/arm64-v8a/libactual.so"));
                zip.write(bytes); zip.closeEntry();
            }
            NativeIntegrity.verifyResolvedLibrary(split.getPath() + "!/lib/arm64-v8a/libactual.so", raw);
            try { NativeIntegrity.verifyResolvedLibrary(split.getPath() + "!/lib/arm64-v8a/libmissing.so", raw); fail(); }
            catch (SecurityException expected) { assertEquals("N71", expected.getMessage()); }
            Files.delete(so.toPath());
            try { NativeIntegrity.verifyResolvedLibrary(so.getPath(), raw); fail(); }
            catch (IOException expected) { } // 不能回退到 APK 或目录中其他库
        } finally {
            Files.deleteIfExists(so.toPath()); Files.deleteIfExists(unrelated.toPath());
            Files.deleteIfExists(split.toPath()); Files.deleteIfExists(directory.toPath());
        }
    }
}
