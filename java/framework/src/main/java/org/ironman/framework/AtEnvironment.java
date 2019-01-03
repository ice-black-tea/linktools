package org.ironman.framework;

import android.app.ActivityManager;
import android.app.ActivityThread;
import android.app.Application;
import android.content.Context;
import android.content.pm.PackageManager;
import android.os.Looper;

import java.io.Closeable;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.lang.ref.WeakReference;

public final class AtEnvironment {

    private static final String DEV_NULL = "/dev/null";
    private static WeakReference<Application> sApplication = null;
    private static WeakReference<PackageManager> sPackageManager = null;
    private static WeakReference<ActivityManager> sActivityManager = null;

    public static Application getApplication() {
        if (sApplication == null) {
            synchronized (AtEnvironment.class) {
                if (sApplication == null) {
                    if (Looper.getMainLooper() == null) {
                        Looper.prepareMainLooper();
                    }
                    if (ActivityThread.currentActivityThread() == null) {
                        runQuietly(new Runnable() {
                            @Override
                            public void run() {
                                ActivityThread.systemMain();
                            }
                        });
                    }
                    sApplication = new WeakReference<>(ActivityThread.currentApplication());
                }
            }
        }

        return sApplication.get();
    }

    public static PackageManager getPackageManager() {
        if (sPackageManager == null) {
            synchronized (AtEnvironment.class) {
                if (sPackageManager == null) {
                    sPackageManager = new WeakReference<>(getApplication().getPackageManager());
                }
            }
        }
        return sPackageManager.get();
    }

    public static ActivityManager getActivityManager() {
        if (sActivityManager == null) {
            synchronized (AtEnvironment.class) {
                if (sActivityManager == null) {
                    sActivityManager = new WeakReference<>((ActivityManager)
                            getApplication().getSystemService(Context.ACTIVITY_SERVICE));
                }
            }
        }
        return sActivityManager.get();
    }

    private static void runQuietly(Runnable runnable) {
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
                // e.printStackTrace();
            }

            runnable.run();

        } finally {
            if (out != System.out) System.setOut(out);
            if (err != System.err) System.setErr(err);
            if (ps != null) closeQuietly(ps);
            if (os != null) closeQuietly(os);
        }
    }

    private static void closeQuietly(Closeable closeable) {
        try {
            closeable.close();
        } catch (IOException e) {
            // e.printStackTrace();
        }
    }
}
