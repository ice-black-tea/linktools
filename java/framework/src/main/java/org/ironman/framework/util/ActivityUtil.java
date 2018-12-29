package org.ironman.framework.util;

import android.annotation.TargetApi;
import android.app.ActivityManager;
import android.content.ComponentName;
import android.content.Intent;
import android.os.Build;
import android.provider.Settings;

import org.ironman.framework.AtEnvironment;

import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.util.List;

public class ActivityUtil {

    public static ComponentName getTopActivity() {
        ActivityManager am = AtEnvironment.getActivityManager();
        List<ActivityManager.RunningTaskInfo> tasks = am.getRunningTasks(0);
        if (tasks != null && tasks.size() > 0) {
            return tasks.get(0).topActivity;
        }
        return null;
    }

    @TargetApi(Build.VERSION_CODES.LOLLIPOP)
    public static void startUsageAccessSettings() {
        startActivity(new Intent(Settings.ACTION_USAGE_ACCESS_SETTINGS));
    }

    public static void startActivity(Intent intent) {
        ActivityManagerService.hook();
        intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
        intent.addFlags(Intent.FLAG_ACTIVITY_MULTIPLE_TASK);
        AtEnvironment.getApplication().startActivity(intent);
    }

    private static class ActivityManagerService implements InvocationHandler {

        private static ActivityManagerService sInstance;

        private Object mAm = null;

        private static void hook() {
            if (sInstance == null) {
                sInstance = new ActivityManagerService();
            } else if (sInstance.mAm != null) {
                return; // hooked
            }

            // android.app.ActivityManagerNative.gDefault
            String targetClass = "android.app.ActivityManagerNative";
            String targetField = "gDefault";
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                // android.app.ActivityManager.IActivityManagerSingleton
                targetClass = "android.app.ActivityManager";
                targetField = "IActivityManagerSingleton";
            }

            try {
                // sdk < 8.0: singleton = android.app.ActivityManagerNative.gDefault
                // sdk >= 8.0: singleton = android.app.ActivityManager.IActivityManagerSingleton
                Object singleton = ReflectUtil.get(targetClass, targetField);

                // am = singleton.get()
                sInstance.mAm = ReflectUtil.invoke(singleton, "get");

                // create am proxy
                Object proxy = Proxy.newProxyInstance(sInstance.mAm.getClass().getClassLoader(),
                        sInstance.mAm.getClass().getInterfaces(), sInstance);

                // singleton.mInstance = proxy
                ReflectUtil.set(singleton, "mInstance", proxy);
            } catch (Exception e) {
                // ignore
            }
        }

        @Override
        public Object invoke(Object proxy, Method method, Object[] args) throws Throwable {
            switch (method.getName()) {
                case "startActivity":
                case "startService":
                case "broadcastIntent":
                    // applicationThread = null;
                    args[0] = null;
                    break;
            }
            return method.invoke(mAm, args);
        }
    }
}


