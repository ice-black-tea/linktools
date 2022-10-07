package org.ironman.framework.bean.app;

import android.content.pm.ApplicationInfo;
import android.content.pm.PackageInfo;
import android.content.pm.PackageParser;

import org.ironman.framework.util.LogUtil;
import org.ironman.framework.util.PackageUtil;

import java.util.ArrayList;
import java.util.List;

/**
 * Created by hu on 18-12-29.
 */

public class FPackage {

    private static final String TAG = FPackage.class.getSimpleName();

    public String name;
    public String appName;
    public int userId;
    public int[] gids;
    public String sourceDir;
    public long versionCode;
    public String versionName;
    public boolean enabled;
    public boolean system;
    public boolean debuggable;
    public boolean allowBackup;

    public List<FPermission> requestedPermissions;
    public List<FPermission> permissions;
    public List<FActivity> activities;
    public List<FService> services;
    public List<FReceiver> receivers;
    public List<FProvider> providers;

    public FPackage(PackageInfo info) {
        this(info, true);
    }

    public FPackage(PackageInfo info, boolean skipParse) {
        name = info.packageName;
        appName = PackageUtil.getApplicationName(info);
        userId = info.applicationInfo.uid;
        gids = info.gids;
        sourceDir = info.applicationInfo.publicSourceDir;
        versionCode = info.versionCode;
        versionName = info.versionName;
        enabled = info.applicationInfo.enabled;
        system = (info.applicationInfo.flags & ApplicationInfo.FLAG_SYSTEM) != 0;
        debuggable = (info.applicationInfo.flags & ApplicationInfo.FLAG_DEBUGGABLE) != 0;
        allowBackup = (info.applicationInfo.flags & ApplicationInfo.FLAG_ALLOW_BACKUP) != 0;

        if (skipParse) {
            return;
        }

        PackageParser.Package pkg = PackageUtil.parsePackage(sourceDir);
        if (pkg == null) {
            LogUtil.w(TAG, "can not parse package: %s (%s)", name, sourceDir);
            return;
        }

        if (pkg.requestedPermissions != null && pkg.requestedPermissions.size() > 0) {
            requestedPermissions = new ArrayList<>(pkg.requestedPermissions.size());
            for (String permission : pkg.requestedPermissions) {
                requestedPermissions.add(new FPermission(permission));
            }
        }

        if (pkg.permissions != null && pkg.permissions.size() > 0) {
            permissions = new ArrayList<>(pkg.permissions.size());
            for (PackageParser.Permission p : pkg.permissions) {
                permissions.add(new FPermission(p.info.name));
            }
        }

        if (pkg.activities != null && pkg.activities.size() > 0) {
            activities = new ArrayList<>(pkg.activities.size());
            for (PackageParser.Activity a : pkg.activities) {
                activities.add(new FActivity(a));
            }
        }

        if (pkg.services != null && pkg.services.size() > 0) {
            services = new ArrayList<>(pkg.services.size());
            for (PackageParser.Service s : pkg.services) {
                services.add(new FService(s));
            }
        }

        if (pkg.receivers != null && pkg.receivers.size() > 0) {
            receivers = new ArrayList<>(pkg.receivers.size());
            for (PackageParser.Activity r : pkg.receivers) {
                receivers.add(new FReceiver(r));
            }
        }

        if (pkg.providers != null && pkg.providers.size() > 0) {
            providers = new ArrayList<>(pkg.providers.size());
            for (PackageParser.Provider p : pkg.providers) {
                providers.add(new FProvider(p));
            }
        }
    }

}
