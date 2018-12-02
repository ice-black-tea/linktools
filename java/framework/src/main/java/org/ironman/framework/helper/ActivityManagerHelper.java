package org.ironman.framework.helper;

import android.app.ActivityManager;
import android.app.Application;
import android.content.Context;

import org.ironman.framework.AtEnvironment;

public class ActivityManagerHelper {

    private static ActivityManagerHelper sInstance = new ActivityManagerHelper();

    public static ActivityManagerHelper get() {
        return sInstance;
    }

    private Application mApplication;
    private ActivityManager mActivityManager;

    private ActivityManagerHelper() {
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
