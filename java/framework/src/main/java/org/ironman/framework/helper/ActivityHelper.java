package org.ironman.framework.helper;

import android.annotation.SuppressLint;
import android.app.ActivityManager;
import android.app.Application;
import android.content.Context;

import org.ironman.framework.AtEnvironment;

public class ActivityHelper {

    @SuppressLint("StaticFieldLeak")
    private static ActivityHelper sInstance = new ActivityHelper();

    public static ActivityHelper get() {
        return sInstance;
    }

    private Application mApplication;
    private ActivityManager mActivityManager;

    private ActivityHelper() {
        mApplication = AtEnvironment.getApplication();
        mActivityManager = (ActivityManager) mApplication.getSystemService(Context.ACTIVITY_SERVICE);
    }

    public Application getApplication() {
        return mApplication;
    }

    public ActivityManager getActivityManager() {
        return mActivityManager;
    }

}
