package org.ironman.framework.util;

import java.io.IOException;

public class ProcessUtil {

    private static final String TAG = ProcessUtil.class.getSimpleName();

    public static String getProcessName(int pid, String defaultValue) {
        try {
            return FileUtil.readString("/proc/" + pid + "/cmdline");
        } catch (IOException e) {
            LogUtil.printStackTrace(TAG, e);
            return defaultValue;
        }
    }
}
