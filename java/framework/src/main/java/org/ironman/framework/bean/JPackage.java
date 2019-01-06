package org.ironman.framework.bean;

import android.content.pm.ActivityInfo;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageInfo;
import android.content.pm.PermissionInfo;
import android.content.pm.ProviderInfo;
import android.content.pm.ServiceInfo;

import org.ironman.framework.util.PackageUtil;

import java.util.ArrayList;
import java.util.List;

/**
 * Created by hu on 18-12-29.
 */

public class JPackage {

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

    public List<JPermission> permissions;
    public List<JActivity> activities;
    public List<JService> services;
    public List<JReceiver> receivers;
    public List<JProvider> providers;

    public JPackage(PackageInfo info) {
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

        if (info.permissions != null) {
            permissions = new ArrayList<>(info.permissions.length);
            for (PermissionInfo p : info.permissions) {
                permissions.add(new JPermission(p));
            }
        }

        if (info.activities != null) {
            activities = new ArrayList<>(info.activities.length);
            for (ActivityInfo a : info.activities) {
                activities.add(new JActivity(a));
            }
        }

        if (info.services != null) {
            services = new ArrayList<>(info.services.length);
            for (ServiceInfo s : info.services) {
                services.add(new JService(s));
            }
        }

        if (info.receivers != null) {
            receivers = new ArrayList<>(info.receivers.length);
            for (ActivityInfo r : info.receivers) {
                receivers.add(new JReceiver(r));
            }
        }

        if (info.providers != null) {
            providers = new ArrayList<>(info.providers.length);
            for (ProviderInfo p : info.providers) {
                providers.add(new JProvider(p));
            }
        }
    }

}
