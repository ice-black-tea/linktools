package org.ironman.framework.helper;

import android.annotation.SuppressLint;
import android.app.ActivityManager;
import android.app.Application;
import android.app.usage.UsageStats;
import android.app.usage.UsageStatsManager;
import android.content.ComponentName;
import android.content.Context;
import android.content.pm.ActivityInfo;
import android.content.pm.ApplicationInfo;
import android.content.pm.ComponentInfo;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.PermissionInfo;
import android.content.pm.ProviderInfo;
import android.content.pm.ServiceInfo;
import android.text.TextUtils;
import android.util.Log;

import org.ironman.framework.AtEnvironment;
import org.ironman.framework.bean.AppInfo;
import org.ironman.framework.bean.AppType;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;
import java.util.SortedMap;
import java.util.TreeMap;

public class PackageHelper {

    @SuppressLint("StaticFieldLeak")
    private static PackageHelper sInstance = new PackageHelper();

    public static PackageHelper get() {
        return sInstance;
    }

    private Application mApplication;
    private PackageManager mPackageManager;

    private PackageHelper() {
        mApplication = AtEnvironment.getApplication();
        mPackageManager = mApplication.getPackageManager();
    }

    public Application getApplication() {
        return mApplication;
    }

    public PackageManager getPackageManager() {
        return mPackageManager;
    }

    public AppInfo getAppInfo(String packageName) {
        Context context = getApplication();
        try {
            PackageInfo packageInfos = context.getPackageManager().getPackageInfo(packageName, -1);
            return new AppInfo(context, packageInfos);
        } catch (PackageManager.NameNotFoundException e) {
            e.printStackTrace();
        }
        return null;
    }

    public List<AppInfo> getInstalledAppInfos() {
        return getInstalledAppInfos(AppType.ALL);
    }

    @SuppressLint("WrongConstant")
    public List<AppInfo> getInstalledAppInfos(AppType type) {
        Context context = getApplication();
        List<AppInfo> appInfos = new ArrayList<>();
        List<PackageInfo> packageInfos = context.getPackageManager().getInstalledPackages(PackageManager.MATCH_DEFAULT_ONLY - 1);
        for (PackageInfo packageInfo : packageInfos) {
            switch (type) {
                case SYSTEM:
                    if (isSystemPackage(packageInfo)) {
                        appInfos.add(new AppInfo(context, packageInfo));
                    }
                    break;
                case NON_SYSTEM:
                    if (!isSystemPackage(packageInfo)) {
                        appInfos.add(new AppInfo(context, packageInfo));
                    }
                    break;
                default:
                    appInfos.add(new AppInfo(context, packageInfo));
                    break;
            }
        }

        Collections.sort(appInfos, new Comparator<AppInfo>() {
            @Override
            public int compare(AppInfo info1, AppInfo info2) {
                int uid1 = info1.getPackageInfo().applicationInfo.uid;
                int uid2 = info2.getPackageInfo().applicationInfo.uid;
                if (uid1 != uid2) {
                    return uid1 > uid2 ? 1 : -1;
                }
                String name1 = info1.getPackageName();
                String name2 = info2.getPackageName();
                return name1.compareTo(name2);
            }
        });

        return appInfos;
    }

    public boolean isSystemPackage(PackageInfo packageInfo) {
        return (packageInfo.applicationInfo.flags & ApplicationInfo.FLAG_SYSTEM) != 0;
    }

    public static String getTaskPackname(Context context) {
        String currentApp = "";
        if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.LOLLIPOP) {
            @SuppressLint("WrongConstant")
            UsageStatsManager usm = (UsageStatsManager) context.getSystemService(Context.USAGE_STATS_SERVICE);
            long time = System.currentTimeMillis();
            List<UsageStats> appList = usm.queryUsageStats(UsageStatsManager.INTERVAL_DAILY, time - 1000 * 1000, time);
            if (appList != null && appList.size() > 0) {
                SortedMap<Long, UsageStats> mySortedMap = new TreeMap<Long, UsageStats>();
                for (UsageStats usageStats : appList) {
                    mySortedMap.put(usageStats.getLastTimeUsed(), usageStats);
                }
                if (!mySortedMap.isEmpty()) {
                    currentApp = mySortedMap.get(mySortedMap.lastKey()).getPackageName();
                }
            }
        } else {
            ActivityManager am = ActivityHelper.get().getActivityManager();
            List<ActivityManager.RunningTaskInfo> tasks = am.getRunningTasks(0);
            currentApp = tasks.get(0).topActivity.getPackageName();
        }
        return currentApp;
    }
}
