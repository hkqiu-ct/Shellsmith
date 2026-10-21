package dev.mocika.shield.loader;

import android.content.Context;
import android.app.Instrumentation;
import android.os.Bundle;
import org.junit.runner.JUnitCore;
import org.junit.runner.Result;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.URL;
import java.net.URLConnection;
import java.net.URLStreamHandler;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.Certificate;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashSet;
import java.util.Set;
import javax.crypto.Cipher;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import javax.net.ssl.HttpsURLConnection;
import org.json.JSONObject;
import org.junit.Test;
import static org.junit.Assert.*;

/** 仅测试 APK 拦截 HTTPS 连接；验证真实 Keystore 和完整客户端协议，不代表 TLS/正式服务验收。 */
public class ByosDeviceContractTest extends Instrumentation {
    private static Context testContext;
    private static Result startupResult;
    // 真正在 Application.attachBaseContext 主线程运行，防止普通单测掩盖启动期 Keystore 故障。
    public static final class StartupApplication extends android.app.Application {
        @Override protected void attachBaseContext(Context base) {
            super.attachBaseContext(base);
            try {
                java.lang.reflect.Method exempt = StubApp.class.getDeclaredMethod("exemptHiddenApi");
                exempt.setAccessible(true);
                exempt.invoke(null);
                testContext = this;
                assertStartupReleased();
                startupResult = JUnitCore.runClasses(ByosDeviceContractTest.class);
                assertStartupReleased();
            } catch (Exception error) { throw new AssertionError(error); }
        }
    }

    private static void assertStartupReleased() throws Exception {
        if (android.os.Build.VERSION.SDK_INT >= 31) return;
        Class<?> type = Class.forName("android.app.ActivityThread");
        assertNull(type.getMethod("currentApplication").invoke(null));
    }

    @Override public void onCreate(Bundle arguments) { super.onCreate(arguments); start(); }
    @Override public void onStart() {
        Result result = startupResult;
        if (result == null) throw new AssertionError("未执行 attachBaseContext 取钥回归");
        Bundle report = new Bundle();
        StringBuilder output = new StringBuilder("\nTests: " + result.getRunCount() + ", failures: " + result.getFailureCount() + "\n");
        for (org.junit.runner.notification.Failure failure : result.getFailures()) output.append(failure.getTrace());
        report.putString(REPORT_KEY_STREAMRESULT, output.toString());
        finish(result.wasSuccessful() ? -1 : 0, report);
    }

    private static final String ENDPOINT = "https://byos-test.invalid";
    private static final String CERT = new String(new char[64]).replace('\0', 'A');
    private final Set<String> consumed = new HashSet<>();
    private String approvedKey;
    private String failure = "";
    private JSONObject last;
    private final byte[] ikm = new byte[32];

    @Test public void 设备批准撤销与加密取钥拒绝路径() throws Exception {
        Arrays.fill(ikm, (byte) 42);
        Context context = testContext;
        java.util.concurrent.ExecutorService threads = java.util.concurrent.Executors.newFixedThreadPool(4);
        KeyPair device;
        try (AutoCloseable startup = ByosProof.startupContext(context)) {
            java.util.List<java.util.concurrent.Future<KeyPair>> keys = new java.util.ArrayList<>();
            for (int i = 0; i < 4; i++) keys.add(threads.submit(() -> ByosProof.deviceKey(context, ENDPOINT, CERT)));
            byte[] first = keys.get(0).get().getPublic().getEncoded();
            for (java.util.concurrent.Future<KeyPair> key : keys) assertArrayEquals(first, key.get().getPublic().getEncoded());
            device = ByosProof.deviceKey(context, ENDPOINT, CERT);
            assertNull(device.getPrivate().getEncoded());
            assertArrayEquals(device.getPublic().getEncoded(), ByosProof.deviceKey(context, ENDPOINT, CERT).getPublic().getEncoded());
            // 已有 Application 时不替换；嵌套调用关闭不能提前清掉外层启动上下文。
            try (AutoCloseable nested = ByosProof.startupContext(context)) {
                assertNull(nested);
            }
        } finally { threads.shutdownNow(); }
        assertStartupReleased();
        URL.setURLStreamHandlerFactory(protocol -> "https".equals(protocol) ? new URLStreamHandler() {
            @Override protected URLConnection openConnection(URL url) {
                assertEquals(ENDPOINT + "/v1/keys/fetch", url.toString());
                return new HttpsURLConnection(url) {
                    final ByteArrayOutputStream request = new ByteArrayOutputStream();
                    JSONObject response;
                    int status;
                    @Override public OutputStream getOutputStream() { return request; }
                    @Override public int getResponseCode() {
                        try {
                            if ("timeout".equals(failure)) new java.util.concurrent.CountDownLatch(1).await();
                            assertFalse(getInstanceFollowRedirects());
                            last = new JSONObject(request.toString("UTF-8"));
                            response = serve(last); status = response == null ? 403 : 200;
                        } catch (Exception e) { throw new AssertionError(e); }
                        return "redirect".equals(failure) ? 302 : status;
                    }
                    @Override public InputStream getInputStream() {
                        return new ByteArrayInputStream(response.toString().getBytes(java.nio.charset.StandardCharsets.UTF_8));
                    }
                    @Override public void connect() { }
                    @Override public void disconnect() { }
                    @Override public boolean usingProxy() { return false; }
                    @Override public String getCipherSuite() { return "测试连接"; }
                    @Override public Certificate[] getLocalCertificates() { return null; }
                    @Override public Certificate[] getServerCertificates() { return null; }
                };
            }
        } : null);
        denied(context); // 未批准的新设备不能获取密钥。
        approvedKey = Base64.getEncoder().encodeToString(device.getPublic().getEncoded());
        assertArrayEquals(ikm, ByosKeyClient.fetch(context, ENDPOINT, "test-token", CERT));
        assertStartupReleased();
        assertFalse(last.has("integrity_token"));
        assertNull(serve(last)); // 同一证明再次提交被拒绝。
        String previousId = last.getString("request_id");
        assertArrayEquals(ikm, ByosKeyClient.fetch(context, ENDPOINT, "test-token", CERT));
        assertStartupReleased();
        assertNotEquals(previousId, last.getString("request_id"));
        for (String bad : new String[]{"mode", "nonce", "raw", "cipher", "redirect", "timeout"}) {
            failure = bad; denied(context);
            assertStartupReleased();
        }
        failure = ""; approvedKey = null; denied(context); // 撤销立即影响后续取钥。
        assertStartupReleased();
    }

    private void denied(Context context) {
        try { ByosKeyClient.fetch(context, ENDPOINT, "test-token", CERT); fail("拒绝路径被放行"); }
        catch (SecurityException expected) {
            String code = "timeout".equals(failure) ? "K10" : "redirect".equals(failure) ? "K03_302"
                    : failure.isEmpty() ? "K03_403" : "K04";
            assertEquals(code, expected.getMessage());
            assertNull(expected.getCause());
        }
    }

    private JSONObject serve(JSONObject request) throws Exception {
        assertEquals("device_approval", request.getString("auth_mode"));
        assertEquals(2, request.getInt("fetch_protocol"));
        assertEquals("test-token", request.getString("token_id"));
        assertEquals(CERT, request.getString("cert_fingerprint"));
        byte[] digest = ByosKeyClient.nonceDigest(ENDPOINT, "test-token", request.getString("package_name"), CERT,
                request.getLong("timestamp"), request.getString("request_id"), "device_approval",
                request.getString("response_public_key"), request.getString("device_public_key"));
        assertEquals(Base64.getUrlEncoder().withoutPadding().encodeToString(digest), request.getString("nonce"));
        PublicKey publicKey = KeyFactory.getInstance("EC").generatePublic(new X509EncodedKeySpec(Base64.getDecoder().decode(request.getString("device_public_key"))));
        Signature signature = Signature.getInstance("SHA256withECDSA"); signature.initVerify(publicKey); signature.update(digest);
        assertTrue(signature.verify(Base64.getDecoder().decode(request.getString("device_signature"))));
        if (!request.getString("device_public_key").equals(approvedKey) || !consumed.add(request.getString("nonce"))) return null;
        byte[] plaintext = new byte[64]; System.arraycopy(digest, 0, plaintext, 0, 32); System.arraycopy(ikm, 0, plaintext, 32, 32);
        Cipher wrapper = Cipher.getInstance("RSA/ECB/OAEPPadding");
        wrapper.init(Cipher.ENCRYPT_MODE, KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(Base64.getDecoder().decode(request.getString("response_public_key")))),
                new OAEPParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, PSource.PSpecified.DEFAULT));
        byte[] ciphertext = wrapper.doFinal(plaintext);
        if ("cipher".equals(failure)) ciphertext[50] ^= 1;
        JSONObject response = new JSONObject().put("fetch_protocol", 2).put("auth_mode", "mode".equals(failure) ? "play_integrity" : "device_approval")
                .put("token_id", "test-token").put("nonce", "nonce".equals(failure) ? "wrong" : request.getString("nonce"))
                .put("wrapped_ikm", Base64.getEncoder().encodeToString(ciphertext));
        if ("raw".equals(failure)) response.put("ikm", Base64.getEncoder().encodeToString(ikm));
        return response;
    }
}
