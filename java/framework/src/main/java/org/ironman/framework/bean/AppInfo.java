package org.ironman.framework.bean;

import android.content.Context;
import android.content.pm.ActivityInfo;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageInfo;
import android.content.pm.ProviderInfo;
import android.content.pm.ServiceInfo;
import android.graphics.drawable.Drawable;

/**
 * Created by hu on 18-11-2.
 */

public class AppInfo {

    private String mAppName = "";
    private String mPackageName = "";
    private Drawable mAppIcon = null;
    private PackageInfo mPackageInfo = null;

    public AppInfo(){}

    public AppInfo(Context context, PackageInfo packageInfo) {
        setPackageInfo(packageInfo);
        setAppName(packageInfo.applicationInfo.loadLabel(context.getPackageManager()).toString());
        setPackageName(packageInfo.packageName);
        setAppIcon( packageInfo.applicationInfo.loadIcon(context.getPackageManager()));
    }

    public String getAppName() {
        return mAppName;
    }

    public void setAppName(String appName) {
        this.mAppName = appName;
    }

    public Drawable getAppIcon() {
        return mAppIcon;
    }

    public void setAppIcon(Drawable appIcon) {
        this.mAppIcon = appIcon;
    }

    public String getPackageName(){
        return mPackageName;
    }

    public void setPackageName(String packageName){
        this.mPackageName = packageName;
    }

    public PackageInfo getPackageInfo() {
        return mPackageInfo;
    }

    public ApplicationInfo getApplicationInfo() {
        return mPackageInfo.applicationInfo;
    }

    public void setPackageInfo(PackageInfo packageInfo){
        this.mPackageInfo = packageInfo;
    }

    public ActivityInfo[] getActivities() {
        return mPackageInfo.activities != null ? mPackageInfo.activities : new ActivityInfo[0];
    }

    public ServiceInfo[] getServices() {
        return mPackageInfo.services != null ? mPackageInfo.services : new ServiceInfo[0];
    }

    public ActivityInfo[] getReceivers() {
        return mPackageInfo.receivers != null ? mPackageInfo.receivers : new ActivityInfo[0];
    }

    public ProviderInfo[] getProviders() {
        return mPackageInfo.providers != null ? mPackageInfo.providers : new ProviderInfo[0];
    }
}
