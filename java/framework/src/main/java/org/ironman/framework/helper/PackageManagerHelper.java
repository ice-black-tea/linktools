package org.ironman.framework.helper;

import android.app.Application;
import android.content.pm.PackageManager;

import org.ironman.framework.AtEnvironment;

public class PackageManagerHelper {

    private static PackageManagerHelper sInstance = new PackageManagerHelper();

    public static PackageManagerHelper get() {
        return sInstance;
    }

    private Application mApplication;
    private PackageManager mPackageManager;

    private PackageManagerHelper() {
        mApplication = AtEnvironment.getApplication();
        mPackageManager = mApplication.getPackageManager();
    }

    public Application getApplication() {
        return mApplication;
    }

    public PackageManager getPackageManager() {
        return mPackageManager;
    }
}
