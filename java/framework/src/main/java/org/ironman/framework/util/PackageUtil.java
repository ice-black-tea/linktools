package org.ironman.framework.util;

import android.annotation.SuppressLint;
import android.app.usage.UsageStats;
import android.app.usage.UsageStatsManager;
import android.content.ComponentName;
import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.graphics.drawable.Drawable;
import android.os.Build;

import org.ironman.framework.AtEnvironment;
import org.ironman.framework.bean.AppType;

import java.util.ArrayList;
import java.util.List;

public class PackageUtil {

    private static String TAG = PackageUtil.class.getSimpleName();

    @SuppressLint({"WrongConstant", "PackageManagerGetSignatures"})
    public static PackageInfo getPackage(String packageName) {
        Context context = AtEnvironment.getApplication();
        try {
            return context.getPackageManager().getPackageInfo(packageName, 0xffff);
        } catch (PackageManager.NameNotFoundException e) {
            LogUtil.printErrStackTrace(TAG, e, null);
        }
        return null;
    }

    public static List<PackageInfo> getInstalledPackages() {
        return getInstalledPackages(AppType.all);
    }

    @SuppressLint("WrongConstant")
    public static List<PackageInfo> getInstalledPackages(AppType type) {
        List<PackageInfo> packageInfos = new ArrayList<>();
        for (PackageInfo packageInfo : AtEnvironment.getPackageManager().getInstalledPackages(0xffff)) {
            switch (type) {
                case system:
                    if (isSystemPackage(packageInfo)) {
                        packageInfos.add(packageInfo);
                    }
                    break;
                case normal:
                    if (!isSystemPackage(packageInfo)) {
                        packageInfos.add(packageInfo);
                    }
                    break;
                default:
                    packageInfos.add(packageInfo);
                    break;
            }
        }

        return packageInfos;
    }

    public static boolean isSystemPackage(PackageInfo packageInfo) {
        return (packageInfo.applicationInfo.flags & ApplicationInfo.FLAG_SYSTEM) != 0;
    }

    public static CharSequence getApplicationName(PackageInfo packageInfo) {
        return packageInfo.applicationInfo.loadLabel(AtEnvironment.getPackageManager());
    }

    public static Drawable getApplicationIcon(PackageInfo packageInfo) {
        return packageInfo.applicationInfo.loadIcon(AtEnvironment.getPackageManager());
    }

    public static String getTopPackage() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP_MR1) {
            UsageStatsManager usm = (UsageStatsManager) AtEnvironment.getApplication()
                    .getSystemService(Context.USAGE_STATS_SERVICE);
            if (usm != null) {
                long end = System.currentTimeMillis();
                long start = end - 1000 * 1000;
                List<UsageStats> uss = usm.queryUsageStats(UsageStatsManager.INTERVAL_DAILY, start, end);
                if (uss == null || uss.size() == 0) {
                    // ActivityUtil.startUsageAccessSettings();
                } else {
                    UsageStats lastStats = null;
                    for (UsageStats stats : uss) {
                        if (lastStats == null || lastStats.getLastTimeUsed() < stats.getLastTimeUsed()) {
                            lastStats = stats;
                        }
                    }
                    if (lastStats != null) {
                        return lastStats.getPackageName();
                    }
                }
            }
        } else {
            ComponentName topActivity = ActivityUtil.getTopActivity();
            if (topActivity != null) {
                return topActivity.getPackageName();
            }
        }
        return null;
    }
}
