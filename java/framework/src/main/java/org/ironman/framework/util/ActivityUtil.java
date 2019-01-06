package org.ironman.framework.util;

import android.annotation.TargetApi;
import android.app.ActivityManager;
import android.content.ComponentName;
import android.content.Intent;
import android.os.Build;
import android.provider.Settings;

import org.ironman.framework.JEnvironment;
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

    public static ComponentName getTopActivity() {
        ActivityManager am = JEnvironment.getActivityManager();
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
        sActivityManagerProxy.get().replaceActivityManagerService();
        intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
        intent.addFlags(Intent.FLAG_ACTIVITY_MULTIPLE_TASK);
        JEnvironment.getApplication().startActivity(intent);
    }
}


