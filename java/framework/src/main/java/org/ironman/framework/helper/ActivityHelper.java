package org.ironman.framework.helper;

import android.annotation.SuppressLint;
import android.annotation.TargetApi;
import android.app.ActivityManager;
import android.content.ComponentName;
import android.content.Intent;
import android.os.Build;
import android.provider.Settings;

import org.ironman.framework.AtEnvironment;

import java.util.List;

public class ActivityHelper {

    @SuppressLint("StaticFieldLeak")
    private static ActivityHelper sInstance = new ActivityHelper();

    public static ActivityHelper get() {
        return sInstance;
    }

    private ActivityHelper() {

    }

    public ComponentName getTopActivity() {
        ActivityManager am = AtEnvironment.getActivityManager();
        List<ActivityManager.RunningTaskInfo> tasks = am.getRunningTasks(0);
        if (tasks != null && tasks.size() > 0) {
            return tasks.get(0).topActivity;
        }
        return null;
    }

    @TargetApi(Build.VERSION_CODES.LOLLIPOP)
    public void startUsageAccessSettings() {
        Intent intent = new Intent(Settings.ACTION_USAGE_ACCESS_SETTINGS);
        intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
        AtEnvironment.getApplication().startActivity(intent);
    }

}
