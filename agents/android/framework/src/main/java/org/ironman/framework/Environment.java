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

public final class Environment {

    private static final String TAG = Environment.class.getSimpleName();

    private static final Singleton<Application> sApplication = new Singleton<Application>() {
        @Override
        protected Application create() {
            if (Looper.getMainLooper() == null) {
                Looper.prepareMainLooper();
            }
            if (ActivityThread.currentActivityThread() == null) {
                CommonUtil.runQuietly(ActivityThread::systemMain);
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
            // adapt to usage stats service
            PackageManager packageManager = application.getPackageManager();
            String name = packageManager.getNameForUid(Process.myUid());
            if (!TextUtils.isEmpty(name)) {
                Object context = ReflectHelper.get().get(application, "mBase");
                ReflectHelper.get().set(context, "mBasePackageName", name);
                ReflectHelper.get().set(context, "mOpPackageName", name);
                Object loadedApk = ReflectHelper.get().get(context, "mPackageInfo");
                ReflectHelper.get().set(loadedApk, "mPackageName", name);
            }
        } catch (Exception e) {
            LogUtil.printStackTrace(TAG, e, null);
        }
    }
}
