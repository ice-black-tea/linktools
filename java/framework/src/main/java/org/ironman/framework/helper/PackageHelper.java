package org.ironman.framework.helper;

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
import org.ironman.framework.util.LogUtil;

import java.util.ArrayList;
import java.util.List;

public class PackageHelper {

    private static String TAG = PackageHelper.class.getSimpleName();

    @SuppressLint("StaticFieldLeak")
    private static PackageHelper sInstance = new PackageHelper();

    public static PackageHelper get() {
        return sInstance;
    }

    private PackageHelper() {

    }

    @SuppressLint({"WrongConstant", "PackageManagerGetSignatures"})
    public PackageInfo getAppInfo(String packageName) {
        Context context = AtEnvironment.getApplication();
        try {
            return context.getPackageManager().getPackageInfo(packageName, 0xffff);
        } catch (PackageManager.NameNotFoundException e) {
            LogUtil.printErrStackTrace(TAG, e, null);
        }
        return null;
    }

    public List<PackageInfo> getInstalledPackages() {
        return this.getInstalledPackages(AppType.all);
    }

    @SuppressLint("WrongConstant")
    public List<PackageInfo> getInstalledPackages(AppType type) {
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

    public boolean isSystemPackage(PackageInfo packageInfo) {
        return (packageInfo.applicationInfo.flags & ApplicationInfo.FLAG_SYSTEM) != 0;
    }

    public CharSequence getApplicationName(PackageInfo packageInfo) {
        return packageInfo.applicationInfo.loadLabel(AtEnvironment.getPackageManager());
    }

    public Drawable getApplicationIcon(PackageInfo packageInfo) {
        return packageInfo.applicationInfo.loadIcon(AtEnvironment.getPackageManager());
    }

    public String getTopPackage() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP_MR1) {
            UsageStatsManager usm = (UsageStatsManager) AtEnvironment.getApplication()
                    .getSystemService(Context.USAGE_STATS_SERVICE);
            if (usm != null) {
                long end = System.currentTimeMillis();
                long start = end - 1000 * 1000;
                List<UsageStats> uss = usm.queryUsageStats(UsageStatsManager.INTERVAL_DAILY, start, end);
                if (uss == null || uss.size() == 0) {
                    ActivityHelper.get().startUsageAccessSettings();
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
            ComponentName topActivity = ActivityHelper.get().getTopActivity();
            if (topActivity != null) {
                return topActivity.getPackageName();
            }
        }
        return null;
    }
}
