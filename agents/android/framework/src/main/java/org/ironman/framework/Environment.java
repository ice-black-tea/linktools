package org.ironman.framework;

import android.app.ActivityManager;
import android.app.ActivityThread;
import android.app.Application;
import android.content.Context;
import android.content.pm.PackageManager;
import android.os.Looper;
import android.os.Process;
import android.text.TextUtils;

import org.ironman.framework.util.CommonUtil;
import org.ironman.framework.util.LogUtil;
import org.ironman.framework.util.ReflectHelper;

import java.io.File;

public final class Environment {

    private static final String TAG = Environment.class.getSimpleName();

    private static final Singleton<Application> sApplication = new Singleton<Application>() {
        @Override
        protected Application create() {
            if (Looper.getMainLooper() == null) {
                Looper.prepareMainLooper();
            }
            if (ActivityThread.currentActivityThread() == null) {
                ActivityThread.systemMain();
                initApplication(ActivityThread.currentApplication());
            }
            return ActivityThread.currentApplication();
        }
    };

    public static Application getApplication() {
        return sApplication.get();
    }

    public static PackageManager getPackageManager() {
        return getApplication().getPackageManager();
    }

    public static String getPackageName() {
        return getApplication().getPackageName();
    }

    public static ActivityManager getActivityManager() {
        return getSystemService(Context.ACTIVITY_SERVICE);
    }

    @SuppressWarnings("unchecked")
    public static <T> T getSystemService(String name) {
        return (T) Environment.getApplication().getSystemService(name);
    }

    private static void initApplication(Application application) {
        try {
            ReflectHelper helper = ReflectHelper.getDefault();
            Object context = helper.get(application, "mBase");
            Object loadedApk = helper.get(context, "mPackageInfo");

            PackageManager packageManager = application.getPackageManager();
            String name = packageManager.getNameForUid(Process.myUid());
            if (!TextUtils.isEmpty(name)) {
                helper.set(context, "mBasePackageName", name);
                helper.set(context, "mOpPackageName", name);
                helper.set(loadedApk, "mPackageName", name);
            }

            String appDir = System.getenv("CLASSPATH");
            if (!TextUtils.isEmpty(appDir)) {
                try {
                    File appDirFile = new File(appDir);
                    helper.set(loadedApk, "mAppDir", appDirFile.getAbsolutePath());
                    helper.set(loadedApk, "mResDir", appDirFile.getAbsolutePath());
                } catch (Exception e) {
                    LogUtil.printStackTrace(TAG, e, null);
                }
            }

            String dataDir = System.getenv("DATA_PATH");
            if (!TextUtils.isEmpty(dataDir)) {
                File dataDirFile = new File(dataDir);
                try {
                    helper.set(loadedApk, "mDataDir", dataDirFile.getAbsolutePath());
                    helper.set(loadedApk, "mDataDirFile", dataDirFile);
                } catch (Exception e) {
                    LogUtil.printStackTrace(TAG, e, null);
                }
                try {
                    helper.set(loadedApk, "mDeviceProtectedDataDirFile", dataDirFile);
                } catch (Exception e) {
                    LogUtil.printStackTrace(TAG, e, null);
                }
                try {
                    helper.set(loadedApk, "mCredentialProtectedDataDirFile", dataDirFile);
                } catch (Exception e) {
                    LogUtil.printStackTrace(TAG, e, null);
                }
                if (!dataDirFile.exists() || !dataDirFile.mkdirs()) {
                    // ignore
                }
            }

            String libDir = System.getenv("LIBRARY_PATH");
            if (!TextUtils.isEmpty(libDir)) {
                File libDirFile = new File(libDir);
                try {
                    helper.set(loadedApk, "mLibDir", libDirFile.getAbsolutePath());
                } catch (Exception e) {
                    LogUtil.printStackTrace(TAG, e, null);
                }
                if (!libDirFile.exists() || !libDirFile.mkdirs()) {
                    // ignore
                }
            }

        } catch (Exception e) {
            LogUtil.printStackTrace(TAG, e, null);
        }
    }
}
