package dev.mocika.shield.acceptance;

import android.app.Instrumentation;
import android.os.Bundle;
import org.json.JSONArray;
import org.json.JSONObject;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.lang.reflect.Method;
import java.lang.reflect.InvocationTargetException;
import java.util.ArrayList;
import java.util.List;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.Callable;
import java.util.concurrent.Executors;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Future;

/** 外部同签名测试 APK 的纯方法探针；业务用例由测试包 assets/cases.json 提供。 */
public final class MethodProbe extends Instrumentation {
    private static final int ROUNDS = 20;
    private boolean benchmark;

    @Override public void onCreate(Bundle args) {
        super.onCreate(args);
        benchmark = args != null && "true".equals(args.getString("benchmark"));
        start();
    }

    /** ponytail: 固定预热与轮换只作限定对照；更短方法需扩大批次并单独控制编译状态，不当作业务 SLA。 */
    private static JSONArray measure(Map<Method, List<Callable<Void>>> groups) throws Exception {
        List<Method> methods = new ArrayList<>(groups.keySet());
        List<JSONArray> samples = new ArrayList<>();
        for (Method method : methods) {
            samples.add(new JSONArray());
            for (int round = 0; round < 100; round++)
                for (Callable<Void> check : groups.get(method)) check.call();
        }
        for (int round = 0; round < 9; round++) {
            for (int offset = 0; offset < methods.size(); offset++) {
                int index = (round + offset) % methods.size();
                List<Callable<Void>> group = groups.get(methods.get(index));
                long begin = System.nanoTime();
                for (int repeat = 0; repeat < ROUNDS; repeat++)
                    for (Callable<Void> check : group) check.call();
                samples.get(index).put(System.nanoTime() - begin);
            }
        }
        JSONArray result = new JSONArray();
        for (int i = 0; i < methods.size(); i++) {
            Method method = methods.get(i);
            int cases = groups.get(method).size();
            result.put(new JSONObject().put("method", method.toGenericString())
                    .put("cases", cases).put("warmup_calls", cases * 100)
                    .put("calls_per_round", cases * ROUNDS).put("round_ns", samples.get(i)));
        }
        return result;
    }

    private static Class<?> type(String name) {
        switch (name) {
            case "int": return int.class;
            case "long": return long.class;
            case "boolean": return boolean.class;
            case "String": return String.class;
            case "Object": return Object.class;
            default: throw new IllegalArgumentException("不支持的用例参数类型：" + name);
        }
    }

    private static Object value(JSONArray array, int index, Class<?> type) throws Exception {
        if (array.isNull(index)) {
            if (type.isPrimitive()) throw new IllegalArgumentException("基本类型不接受 null");
            return null;
        }
        if (type == Object.class) {
            Object value = array.get(index);
            if (value instanceof String || value instanceof Number || value instanceof Boolean) return value;
            throw new IllegalArgumentException("Object 用例仅支持标量包装值和 null");
        }
        if (type == int.class) return array.getInt(index);
        if (type == long.class) return array.getLong(index);
        if (type == boolean.class) return array.getBoolean(index);
        return array.getString(index);
    }

    @Override public void onStart() {
        Bundle result = new Bundle();
        ExecutorService pool = Executors.newFixedThreadPool(4);
        try {
            ByteArrayOutputStream bytes = new ByteArrayOutputStream();
            try (InputStream in = getContext().getAssets().open("cases.json")) {
                byte[] buffer = new byte[4096];
                for (int n; (n = in.read(buffer)) != -1;) {
                    if (bytes.size() + n > 1024 * 1024) throw new IllegalArgumentException("用例文件过大");
                    bytes.write(buffer, 0, n);
                }
            }
            JSONArray cases = new JSONArray(bytes.toString("UTF-8"));
            if (cases.length() == 0 || cases.length() > 10000) throw new IllegalArgumentException("用例数量无效");
            ClassLoader loader = getTargetContext().getClassLoader();
            List<Callable<Void>> checks = new ArrayList<>();
            Map<Method, List<Callable<Void>>> groups = new LinkedHashMap<>();
            for (int i = 0; i < cases.length(); i++) {
                JSONObject item = cases.getJSONObject(i);
                Class<?> owner = loader.loadClass(item.getString("class"));
                String receiver = item.getString("receiver");
                final Object target;
                switch (receiver) {
                    case "static": target = null; break;
                    case "constructor": target = owner.getDeclaredConstructor().newInstance(); break;
                    case "INSTANCE": target = owner.getField("INSTANCE").get(null); break;
                    default: throw new IllegalArgumentException("不支持的接收者：" + receiver);
                }
                JSONArray names = item.getJSONArray("types"), values = item.getJSONArray("args");
                if (names.length() != values.length()) throw new IllegalArgumentException("参数数量不一致");
                Class<?>[] types = new Class<?>[names.length()];
                Object[] args = new Object[types.length];
                for (int j = 0; j < types.length; j++) {
                    types[j] = type(names.getString(j)); args[j] = value(values, j, types[j]);
                }
                Method method = owner.getDeclaredMethod(item.getString("method"), types);
                method.setAccessible(true);
                if (item.has("expected") == item.has("expected_exception"))
                    throw new IllegalArgumentException("预期返回值与异常类型必须且只能提供一个");
                final String expectedException = item.has("expected_exception") ? item.getString("expected_exception") : null;
                Object expected = item.isNull("expected") ? null : item.get("expected");
                // ponytail: 只比较标量纯方法，带状态/副作用/浮点容差的方法应使用业务专用测试。
                if (method.getReturnType() == long.class && expected instanceof Number)
                    expected = ((Number) expected).longValue();
                final Object wanted = expected;
                final int index = i;
                Callable<Void> check = () -> {
                    final Object actual;
                    try { actual = method.invoke(target, args); }
                    catch (InvocationTargetException error) {
                        if (expectedException != null && error.getCause() != null
                                && expectedException.equals(error.getCause().getClass().getName())) return null;
                        throw error;
                    }
                    if (expectedException != null || !Objects.equals(wanted, actual))
                        throw new AssertionError("用例返回值不一致，索引=" + index);
                    return null;
                };
                checks.add(check);
                groups.computeIfAbsent(method, ignored -> new ArrayList<>()).add(check);
            }
            for (Callable<Void> check : checks) check.call();
            long begin = System.nanoTime();
            for (int round = 0; round < ROUNDS; round++) for (Callable<Void> check : checks) check.call();
            result.putLong("sequential_ns", System.nanoTime() - begin);
            if (benchmark) {
                result.putString("method_benchmarks", measure(groups).toString());
                result.putInt("benchmark_calls", checks.size() * (100 + 9 * ROUNDS));
            }
            List<Callable<Void>> workers = new ArrayList<>();
            for (int thread = 0; thread < 4; thread++) workers.add(() -> {
                for (int round = 0; round < ROUNDS; round++) for (Callable<Void> check : checks) check.call();
                return null;
            });
            for (Future<Void> future : pool.invokeAll(workers)) future.get();
            result.putInt("cases", checks.size());
            result.putInt("calls", checks.size() * (1 + 5 * ROUNDS));
            result.putString("acceptance", "passed");
            finish(0, result);
        } catch (Throwable error) {
            android.util.Log.e("MOCIKA_METHOD_PROBE", "方法验收失败", error);
            result.putString("acceptance", "failed");
            result.putString("error", error.toString());
            finish(1, result);
        } finally { pool.shutdownNow(); }
    }
}
