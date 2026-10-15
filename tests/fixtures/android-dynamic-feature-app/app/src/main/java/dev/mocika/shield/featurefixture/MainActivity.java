package dev.mocika.shield.featurefixture;

import android.app.Activity;
import android.os.Bundle;
import android.util.Log;

import java.io.BufferedReader;
import java.io.InputStreamReader;

public final class MainActivity extends Activity {
    // These exact paths are also consumed through MocikaPlayDelivery after Play installs
    // the deferred pack. Keeping the literals in DEX makes PAS2 selection auditable.
    public static final String FAST_ASSET = "fast/mocika_fast_asset.txt";
    public static final String ON_DEMAND_ASSET = "ondemand/mocika_ondemand_asset.txt";

    @Override
    protected void onCreate(Bundle state) {
        super.onCreate(state);
        try {
            Class<?> probe = Class.forName("dev.mocika.shield.featurefixture.feature.FeatureProbe");
            String value = (String) probe.getDeclaredMethod("message", int.class).invoke(null, 7);
            if (!"feature-14".equals(value)) throw new IllegalStateException(value);
            Log.i("MocikaFeature", "MOCIKA_DYNAMIC_FEATURE_OK");
            if (getIntent().getBooleanExtra("verify_native_vmp", false)) {
                Class<?> conditional = Class.forName("dev.mocika.shield.featurefixture.conditional.ConditionalProbe");
                Object calls = conditional.getDeclaredMethod("verifyNative").invoke(null);
                if (!Integer.valueOf(1000).equals(calls)) throw new IllegalStateException("Native 检查未完成");
                Log.i("MocikaFeature", "NATIVE_VMP_APP_OK calls=1000");
            }
            try (BufferedReader reader = new BufferedReader(
                    new InputStreamReader(getAssets().open("mocika_install_asset.txt")))) {
                Log.i("MocikaFeature", reader.readLine());
            }
        } catch (Exception failure) {
            throw new IllegalStateException("dynamic feature or install-time asset unavailable", failure);
        }
    }
}
