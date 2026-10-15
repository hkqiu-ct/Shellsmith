package dev.mocika.shield.featurefixture.conditional;

public final class ConditionalProbe {
    private ConditionalProbe() {}

    public static String assetPath() {
        return "conditional/mocika_conditional_asset.txt";
    }

    public static native int nativeScore(int value);

    public static int verifyNative() {
        System.loadLibrary("mocikaconditional");
        // 输入限定为 0..999，与 Native 探针一致，避免原 C 样本的有符号乘法溢出。
        for (int value = 0; value < 1000; value++) {
            int expected = value;
            for (int round = 0; round < 4; round++) {
                expected = (expected * 17 + round) ^ (expected >> 2);
            }
            if (nativeScore(value) != expected) {
                throw new IllegalStateException("Native 返回值不一致：" + value);
            }
        }
        return 1000;
    }
}

