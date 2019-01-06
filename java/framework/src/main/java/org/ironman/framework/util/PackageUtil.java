package org.ironman.framework.util;

import android.annotation.SuppressLint;
import android.app.usage.UsageStats;
import android.app.usage.UsageStatsManager;
import android.content.ComponentName;
import android.content.Context;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.PackageParser;
import android.graphics.drawable.Drawable;
import android.os.Build;

import org.ironman.framework.JEnvironment;
import org.ironman.framework.compat.PackageParserCompat;

import java.io.File;
import java.util.ArrayList;
import java.util.List;

public class PackageUtil {

    private static final String TAG = PackageUtil.class.getSimpleName();
    public static final int DEFAULT_PACKAGE_INFO_FLAGS = 0xffff;
    public static final int DEFAULT_PARSE_PACKAGE_FLAGS = 0xffffffff;

    public static List<PackageInfo> getPackages(String... packageNames) {
        return getPackages(packageNames, DEFAULT_PACKAGE_INFO_FLAGS);
    }

    public static List<PackageInfo> getPackages(String[] packageNames, int flags) {
        List<PackageInfo> packages = new ArrayList<>();
        for (String packageName : packageNames) {
            try {
                packages.add(JEnvironment.getPackageManager().getPackageInfo(packageName, flags));
            } catch (PackageManager.NameNotFoundException e) {
                LogUtil.printErrStackTrace(TAG, e, null);
            }
        }
        return packages;
    }

    @SuppressLint("WrongConstant")
    public static List<PackageInfo> getInstalledPackages() {
        return getInstalledPackages(DEFAULT_PACKAGE_INFO_FLAGS);
    }

    @SuppressLint("WrongConstant")
    public static List<PackageInfo> getInstalledPackages(int flags) {
        return JEnvironment.getPackageManager().getInstalledPackages(flags);
    }

    public static PackageParser.Package parsePackage(String packagePath) {
        return PackageParserCompat.parsePackage(new File(packagePath), DEFAULT_PARSE_PACKAGE_FLAGS);
    }

    public static PackageParser.Package parsePackage(String packagePath, int flags) {
        return PackageParserCompat.parsePackage(new File(packagePath), flags);
    }

    public static String getApplicationName(PackageInfo packageInfo) {
        return packageInfo.applicationInfo.loadLabel(JEnvironment.getPackageManager()).toString();
    }

    public static Drawable getApplicationIcon(PackageInfo packageInfo) {
        return packageInfo.applicationInfo.loadIcon(JEnvironment.getPackageManager());
    }

    public static String getTopPackage() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP_MR1) {
            UsageStatsManager usm = JEnvironment.getSystemService(Context.USAGE_STATS_SERVICE);
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
