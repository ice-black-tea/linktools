package org.ironman.framework.util;

import android.annotation.TargetApi;
import android.app.ActivityManager;
import android.content.Intent;
import android.os.Build;
import android.provider.Settings;

import org.ironman.framework.Environment;
import org.ironman.framework.Singleton;
import org.ironman.framework.proxy.ActivityManagerProxy;

import java.util.List;

public class ActivityUtil {

    private static final String TAG = ActivityUtil.class.getSimpleName();

    private static final Singleton<ActivityManagerProxy> sActivityManagerProxy = new Singleton<ActivityManagerProxy>() {
        @Override
        protected ActivityManagerProxy create() {
            return new ActivityManagerProxy();
        }
    };

    public static String getTopActivity() {
        ActivityManager am = Environment.getActivityManager();
        List<ActivityManager.RunningTaskInfo> tasks = am.getRunningTasks(0);
        if (tasks != null && tasks.size() > 0) {
            return tasks.get(0).topActivity.getClassName();
        }
        return null;
    }

    @TargetApi(Build.VERSION_CODES.LOLLIPOP)
    public static void startUsageAccessSettings() {
        startActivity(new Intent(Settings.ACTION_USAGE_ACCESS_SETTINGS));
    }

    public static void startActivity(Intent intent) {
        sActivityManagerProxy.get().replaceActivityManagerService();
        intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
        intent.addFlags(Intent.FLAG_ACTIVITY_MULTIPLE_TASK);
        Environment.getApplication().startActivity(intent);
    }

    public static void startService(Intent intent) {
        sActivityManagerProxy.get().replaceActivityManagerService();
        Environment.getApplication().startService(intent);
    }

    public static void sendBroadcast(Intent intent) {
        sActivityManagerProxy.get().replaceActivityManagerService();
        Environment.getApplication().sendBroadcast(intent);
    }
}


