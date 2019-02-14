package org.ironman.framework.util;

import java.io.Closeable;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.PrintStream;

/**
 * Created by hu on 19-2-13.
 */

public class CommonUtil {

    private static final String TAG = CommonUtil.class.getSimpleName();
    private static final String DEV_NULL = "/dev/null";

    public static int parseInt(Object object) {
        return parseInt(object, 10, 0);
    }

    public static int parseInt(Object object, int defValue) {
        return parseInt(object, 10, defValue);
    }

    public static int parseInt(Object object, int radix, int defValue) {
        try {
            return Integer.parseInt(String.valueOf(object));
        } catch (Exception e) {
            return defValue;
        }
    }

    public static long parseLong(Object object) {
        return parseLong(object, 10, 0);
    }

    public static long parseLong(Object object, long defValue) {
        return parseLong(object, 10, defValue);
    }

    public static long parseLong(Object object, int radix, long defValue) {
        try {
            return Long.parseLong(String.valueOf(object), radix);
        } catch (Exception e) {
            return defValue;
        }
    }

    public static void closeQuietly(Closeable closeable) {
        try {
            if (closeable != null) {
                closeable.close();
            }
        } catch (IOException e) {
            LogUtil.printErrStackTrace(TAG, e, null);
        }
    }

    public static void runQuietly(Runnable runnable) {
        PrintStream out = System.out;
        PrintStream err = System.err;
        FileOutputStream os = null;
        PrintStream ps = null;

        try {
            try {
                os = new FileOutputStream(DEV_NULL);
                ps = new PrintStream(os);
                System.setOut(ps);
                System.setErr(ps);
            } catch (Exception e) {
                LogUtil.printErrStackTrace(TAG, e, null);
            }

            runnable.run();

        } finally {
            if (out != System.out) {
                System.setOut(out);
            }
            if (err != System.err) {
                System.setErr(err);
            }
            CommonUtil.closeQuietly(ps);
            CommonUtil.closeQuietly(os);
        }
    }


}
