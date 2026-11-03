package dev.mocika.shield.loader;

import android.content.Context;
import android.content.SharedPreferences;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.util.Log;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

public class ARouterCompat {

    private static final String TAG = "rx";
    private static final String AROUTER_ROUTES_PACKAGE = "com.alibaba.android.arouter.routes.";
    private static final String ROUTE_LIST_ASSET = "arouter_routes.txt";
    private static final String ROUTE_LIST_RTAP = "arouter_routes.rtap";
    private static final String CACHE_NAME = "SP_AROUTER_CACHE";
    private static final String CACHE_ROUTE_MAP = "ROUTER_MAP";
    private static final String CACHE_VERSION_NAME = "LAST_VERSION_NAME";
    private static final String CACHE_VERSION_CODE = "LAST_VERSION_CODE";
    private static volatile boolean prepared;

    /**
     * 从 assets/arouter_routes.rtap/.txt 读取路由表类名并写入 ARouter 自有缓存。
     * 路由表由 shield-cli 加固时静态扫描 DEX 生成，不依赖 DexFile API，兼容 API 21 及以上。
     * 必须在任何 ContentProvider / 宿主 Application.onCreate() 之前调用，确保覆盖安装后
     * versionCode 变化时首次启动也能读到当前路由表。
     */
    public static void prepareARouterRouteMap(Context context) {
        if (prepared) {
            return;
        }
        try {
            Class<?> logisticsCenterClass = Class.forName(
                    "com.alibaba.android.arouter.core.LogisticsCenter",
                    false,
                    context.getClassLoader());

            Set<String> routeClassNames = readRouteList(context);
            if (routeClassNames.isEmpty()) {
                Log.i(TAG, "A07 routeCount=0");
                return;
            }

            PackageInfo packageInfo = context.getPackageManager().getPackageInfo(
                    context.getPackageName(), 0);
            int versionCode = packageInfo.versionCode;
            SharedPreferences preferences =
                    context.getSharedPreferences(CACHE_NAME, Context.MODE_PRIVATE);
            // 与 ARouter 的失效条件一致：版本号或版本名任一变化都要重新注册。
            boolean versionChanged = isVersionChanged(
                    versionCode,
                    packageInfo.versionName,
                    preferences.getInt(CACHE_VERSION_CODE, -1),
                    preferences.getString(CACHE_VERSION_NAME, null));
            boolean cacheMissing = isRouteCacheMissing(
                    preferences.getStringSet(CACHE_ROUTE_MAP, null));
            boolean preRegister = shouldPreRegister(
                    context.getApplicationInfo().flags, versionChanged, cacheMissing);

            SharedPreferences.Editor editor = preferences
                    .edit()
                    .putStringSet(CACHE_ROUTE_MAP, new LinkedHashSet<>(routeClassNames))
                    .putString(CACHE_VERSION_NAME, packageInfo.versionName)
                    .putInt(CACHE_VERSION_CODE, versionCode);

            // ARouter.init() 紧接着读取缓存，必须同步落盘，不能使用异步 apply()。
            if (!editor.commit()) {
                Log.w(TAG, "A01");
                return;
            }

            // 覆盖安装/清数据/调试包不能只依赖 ARouter 自己读缓存：
            // 加密 DEX 不在 sourceDir 中，ARouter 扫描不到真实路由类。
            if (preRegister) {
                registerRoutes(logisticsCenterClass, routeClassNames);
            }
            prepared = true;
            Log.i(TAG, "A06 routeCount=" + routeClassNames.size()
                    + " versionCode=" + versionCode
                    + " versionChanged=" + versionChanged
                    + " cacheMissing=" + cacheMissing
                    + " preRegister=" + preRegister);
        } catch (ClassNotFoundException ignored) {
        } catch (PackageManager.NameNotFoundException e) {
            Log.w(TAG, "A02", e);
        } catch (Exception e) {
            Log.e(TAG, "A03", e);
        }
    }

    private static void registerRoutes(Class<?> logisticsCenterClass, Set<String> routeClassNames)
            throws Exception {
        Method registerMethod = logisticsCenterClass.getDeclaredMethod("register", String.class);
        registerMethod.setAccessible(true);
        for (String className : routeClassNames) {
            try {
                registerMethod.invoke(null, className);
            } catch (Exception e) {
                Log.w(TAG, "A04", e);
            }
        }
    }

    static boolean shouldPreRegister(int applicationFlags) {
        return (applicationFlags & ApplicationInfo.FLAG_DEBUGGABLE) != 0;
    }

    /** 覆盖安装/清数据后缓存失效，也必须主动注册，不能只依赖 ARouter 扫描加密 APK。 */
    static boolean shouldPreRegister(int applicationFlags, boolean versionChanged, boolean cacheMissing) {
        return shouldPreRegister(applicationFlags) || versionChanged || cacheMissing;
    }

    /**
     * ARouter 用版本名和版本号共同判断缓存是否有效；版本名为空时也会强制重新扫描。
     * 加密 DEX 不在 sourceDir 中，扫描结果必为空，因此这里必须按同样条件预注册。
     */
    static boolean isVersionChanged(
            int currentCode, String currentName, int cachedCode, String cachedName) {
        return currentCode != cachedCode
                || currentName == null
                || currentName.isEmpty()
                || !currentName.equals(cachedName);
    }

    /** ARouter 上一次扫描可能写入空集合；空集合等同于缓存缺失。 */
    static boolean isRouteCacheMissing(Set<String> cachedRoutes) {
        return cachedRoutes == null || cachedRoutes.isEmpty();
    }

    private static Set<String> readRouteList(Context context) {
        List<String> lines = new ArrayList<>();
        try {
            try (InputStream is = context.getAssets().open(ROUTE_LIST_RTAP)) {
                lines = splitLines(Ld.z(readAll(is), 1));
            } catch (java.io.FileNotFoundException encryptedAbsent) {
                try (InputStream is = context.getAssets().open(ROUTE_LIST_ASSET);
                     BufferedReader reader = new BufferedReader(new InputStreamReader(is, "UTF-8"))) {
                    String line;
                    while ((line = reader.readLine()) != null) {
                        lines.add(line);
                    }
                }
            }
        } catch (java.io.FileNotFoundException e) {
            // 文件不存在：宿主未使用 ARouter 或已通过 arouter-register plugin 编译期注入，属正常情况
        } catch (Exception e) {
            Log.w(TAG, "A05", e);
        }
        return filterRouteClassNames(lines);
    }

    private static byte[] readAll(InputStream input) throws java.io.IOException {
        java.io.ByteArrayOutputStream output = new java.io.ByteArrayOutputStream();
        byte[] buffer = new byte[8192];
        int read;
        while ((read = input.read(buffer)) != -1) {
            output.write(buffer, 0, read);
        }
        return output.toByteArray();
    }

    private static List<String> splitLines(byte[] plain) throws java.io.UnsupportedEncodingException {
        List<String> result = new ArrayList<>();
        for (String line : new String(plain, "UTF-8").split("\\r?\\n")) {
            if (!line.isEmpty()) result.add(line);
        }
        return result;
    }

    static Set<String> filterRouteClassNames(Iterable<String> lines) {
        Set<String> names = new LinkedHashSet<>();
        for (String line : lines) {
            if (line == null) {
                continue;
            }
            String className = line.trim();
            if (className.startsWith(AROUTER_ROUTES_PACKAGE)) {
                names.add(className);
            }
        }
        return names;
    }
}
