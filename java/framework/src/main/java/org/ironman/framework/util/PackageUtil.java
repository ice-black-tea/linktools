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

import java.util.ArrayList;
import java.util.List;

public class PackageUtil {

    private static final String TAG = PackageUtil.class.getSimpleName();
    private static final int GET_INFO_FLAGS = 0xffff;

    @SuppressLint({"WrongConstant", "PackageManagerGetSignatures"})
    public static List<PackageInfo> getPackages(String... packageNames) {
        List<PackageInfo> packages = new ArrayList<>();
        for (String packageName : packageNames) {
            try {
                packages.add(AtEnvironment.getPackageManager().getPackageInfo(packageName, GET_INFO_FLAGS));
            } catch (PackageManager.NameNotFoundException e) {
                LogUtil.printErrStackTrace(TAG, e, null);
            }
        }
        return packages;
    }

    @SuppressLint("WrongConstant")
    public static List<PackageInfo> getInstalledPackages() {
        return AtEnvironment.getPackageManager().getInstalledPackages(GET_INFO_FLAGS);
    }

    public static String getApplicationName(PackageInfo packageInfo) {
        return packageInfo.applicationInfo.loadLabel(AtEnvironment.getPackageManager()).toString();
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
                    ActivityUtil.startUsageAccessSettings();
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
