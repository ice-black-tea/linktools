package org.ironman.framework;

import android.app.ActivityThread;
import android.app.Application;
import android.os.Looper;

import com.beust.jcommander.internal.Nullable;

import java.io.Closeable;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.lang.ref.WeakReference;

public final class AtEnvironment {

    private static WeakReference<Application> sApplication = null;

    public static Application getApplication() {
        
        if (sApplication != null) {
            return sApplication.get();
        }

        synchronized (AtEnvironment.class) {

            if (Looper.getMainLooper() == null) {
                Looper.prepareMainLooper();
            }

            if (ActivityThread.currentActivityThread() == null) {
                runSilently(new Runnable() {
                    @Override
                    public void run() {
                        ActivityThread.systemMain();
                    }
                });
            }
        }

        sApplication = new WeakReference<>(ActivityThread.currentApplication());

        return sApplication.get();
    }

    private static void runSilently(Runnable runnable) {
        PrintStream out = System.out;
        PrintStream err = System.err;
        FileOutputStream os = null;
        PrintStream ps = null;
        try {
            try {
                os = new FileOutputStream("/dev/null");
                ps = new PrintStream(os);
                System.setOut(ps);
                System.setErr(ps);
            } catch (Exception e) {
                // e.printStackTrace();
            }

            runnable.run();

        } finally {
            if (out != System.out) System.setOut(out);
            if (err != System.err) System.setOut(err);
            if (ps != null) closeSilently(ps);
            if (os != null) closeSilently(os);
        }
    }

    private static void closeSilently(Closeable closeable) {
        try {
            closeable.close();
        } catch (IOException e) {
            // e.printStackTrace();
        }
    }
}
