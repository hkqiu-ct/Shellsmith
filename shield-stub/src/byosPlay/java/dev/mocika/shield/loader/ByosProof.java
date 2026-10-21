package dev.mocika.shield.loader;

import android.content.Context;
import android.content.ContextWrapper;
import android.content.Intent;
import android.content.ServiceConnection;
import com.google.android.gms.tasks.Tasks;
import com.google.android.play.core.integrity.IntegrityManagerFactory;
import com.google.android.play.core.integrity.IntegrityTokenRequest;
import java.security.KeyPair;
import java.util.concurrent.TimeUnit;

/** 仅 Play 资源编译此实现，失败不降级到设备授权。 */
final class ByosProof {
    static final String MODE = "play_integrity";
    static final int MIN_API = 29;
    static AutoCloseable startupContext(Context ctx) { return null; }
    static KeyPair deviceKey(Context ctx, String endpoint, String certificate) { return null; }
    static String integrityToken(Context ctx, String nonce) throws Exception {
        return Tasks.await(IntegrityManagerFactory.create(new IntegrityContext(ctx)).requestIntegrityToken(
                IntegrityTokenRequest.builder().setNonce(nonce).build()), 5, TimeUnit.SECONDS).token();
    }

    // attachBaseContext 正在等待密钥，连接回调不能排队到同一主线程。
    // ponytail: 只使用 API 29+ 的公开接口；旧系统如需支持须另做异步启动流程。
    static final class IntegrityContext extends ContextWrapper {
        IntegrityContext(Context base) { super(base); }
        @Override public Context getApplicationContext() { return this; }
        @Override public boolean bindService(Intent intent, ServiceConnection connection, int flags) {
            return getBaseContext().bindService(intent, flags, Runnable::run, connection);
        }
    }
}
