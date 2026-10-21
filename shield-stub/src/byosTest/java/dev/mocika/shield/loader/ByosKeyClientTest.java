package dev.mocika.shield.loader;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.spec.MGF1ParameterSpec;
import java.util.Arrays;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import org.junit.Test;
import static org.junit.Assert.*;

public class ByosKeyClientTest {
    @Test public void 取钥诊断保留分类且不泄漏原始异常() {
        Throwable[] errors = {new java.net.UnknownHostException("private-host"),
                new javax.net.ssl.SSLHandshakeException("private-certificate"),
                new java.net.SocketTimeoutException("private-url"),
                new java.net.ConnectException("private-address"), new java.io.IOException("private-body"),
                new SecurityException("K03_403"), new SecurityException("K03_403 secret"),
                new javax.crypto.BadPaddingException("private-ciphertext"),
                new java.security.KeyStoreException("private-alias"), new InterruptedException("private-task")};
        String[] codes = {"K12", "K13", "K10", "K14", "K15", "K03_403", "K01", "K04", "K16", "K11"};
        for (int i = 0; i < errors.length; i++) {
            SecurityException result = ByosKeyClient.failure(new java.util.concurrent.ExecutionException(errors[i]));
            assertEquals(codes[i], result.getMessage());
            assertNull(result.getCause());
            assertEquals(codes[i], ByosKeyClient.failure(result).getMessage());
        }
    }

    @Test public void nonce绑定授权方式与两份公钥() throws Exception {
        String cert = new String(new char[64]).replace('\0', 'A');
        String id = new String(new char[43]).replace('\0', 'A');
        // 此向量只检查规范化；真实请求的两个公钥字段必须是对应算法的 DER SPKI。
        String[] fields = {"https://keys.example/app", "test-token", "com.example.app", cert,
                "1802995200", id, "device_approval", "response-key", "device-key"};
        byte[] digest = digest(fields);
        assertEquals("GhvW6Ivuv3D_eb-O3rRDRkmtUiCYxpZSFsGK5Nha-pM", Base64.getUrlEncoder().withoutPadding().encodeToString(digest));
        for (int field = 0; field < fields.length; field++) {
            String[] changed = fields.clone(); changed[field] += field == 4 ? "1" : "X";
            assertFalse(Arrays.equals(digest, digest(changed)));
        }
    }

    private static byte[] digest(String[] f) throws Exception {
        return ByosKeyClient.nonceDigest(f[0], f[1], f[2], f[3], Long.parseLong(f[4]), f[5], f[6], f[7], f[8]);
    }

    @Test public void OAEP封装拒绝篡改错误密钥与不同请求() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA"); generator.initialize(2048);
        KeyPair pair = generator.generateKeyPair();
        byte[] digest = MessageDigest.getInstance("SHA-256").digest("测试请求".getBytes(StandardCharsets.UTF_8));
        byte[] ikm = new byte[32]; Arrays.fill(ikm, (byte) 42);
        byte[] plaintext = new byte[64]; System.arraycopy(digest, 0, plaintext, 0, 32); System.arraycopy(ikm, 0, plaintext, 32, 32);
        Cipher server = Cipher.getInstance("RSA/ECB/OAEPPadding");
        server.init(Cipher.ENCRYPT_MODE, pair.getPublic(), new OAEPParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, PSource.PSpecified.DEFAULT));
        String wrapped = Base64.getEncoder().encodeToString(server.doFinal(plaintext));
        assertArrayEquals(ikm, ByosKeyClient.unwrap(wrapped, pair.getPrivate(), digest));
        try { ByosKeyClient.unwrap(wrapped, pair.getPrivate(), new byte[32]); fail("接受错误请求"); } catch (SecurityException expected) { }
        try { ByosKeyClient.unwrap(wrapped, generator.generateKeyPair().getPrivate(), digest); fail("接受错误密钥"); } catch (java.security.GeneralSecurityException expected) { }
        byte[] tampered = Base64.getDecoder().decode(wrapped); tampered[100] ^= 1;
        try { ByosKeyClient.unwrap(Base64.getEncoder().encodeToString(tampered), pair.getPrivate(), digest); fail("接受篡改"); } catch (java.security.GeneralSecurityException expected) { }
        for (String invalid : new String[]{wrapped.substring(1), wrapped + "\n", Base64.getEncoder().encodeToString(ikm)}) {
            try { ByosKeyClient.unwrap(invalid, pair.getPrivate(), digest); fail("接受错误编码或明文 IKM"); } catch (SecurityException expected) { }
        }
        // OAEP 明确使用 MGF1-SHA256，不接受部分平台的默认 MGF1-SHA1。
        server.init(Cipher.ENCRYPT_MODE, pair.getPublic(), new OAEPParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA1, PSource.PSpecified.DEFAULT));
        try { ByosKeyClient.unwrap(Base64.getEncoder().encodeToString(server.doFinal(plaintext)), pair.getPrivate(), digest); fail("接受不同算法参数"); } catch (java.security.GeneralSecurityException expected) { }
    }

    @Test public void 端点拒绝非HTTPS与凭据及重定向参数() throws Exception {
        assertEquals("keys.example", ByosKeyClient.endpoint("https://keys.example/api").getHost());
        for (String url : new String[]{"http://keys.example", "https://a:b@keys.example", "https://keys.example?q=x", "https://keys.example#x", " https://keys.example", "https://keys.example\\bad", "https://keys.example\n"}) {
            try { ByosKeyClient.endpoint(url); fail("错误端点被接受"); }
            catch (Exception expected) { }
        }
    }
}
