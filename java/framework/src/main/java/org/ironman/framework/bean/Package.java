package org.ironman.framework.bean;

import android.content.pm.ActivityInfo;
import android.content.pm.ApplicationInfo;
import android.content.pm.ComponentInfo;
import android.content.pm.PackageInfo;
import android.content.pm.PermissionInfo;
import android.content.pm.ProviderInfo;
import android.content.pm.ServiceInfo;
import android.text.TextUtils;

import org.ironman.framework.util.PackageUtil;
import org.ironman.framework.util.PermissionUtil;

import java.util.ArrayList;
import java.util.List;

/**
 * Created by hu on 18-12-29.
 */

public class Package {

    public static class Permission {
        public String name;
        public PermissionUtil.Protection protection;

        private Permission(String name) {
            this.name = name;
            this.protection = PermissionUtil.getProtection(name);
        }

        private Permission(PermissionInfo info) {
            this.name = info.name;
            this.protection = PermissionUtil.getProtection(info);
        }

    }

    public static class Component {
        public String name;
        public boolean exported;
        public boolean enabled;

        private Component(ComponentInfo info) {
            name = info.name;
            exported = info.exported;
            enabled = info.enabled;
        }
    }


    public static class Activity extends Component {
        public Permission permission;

        private Activity(ActivityInfo info) {
            super(info);
            if (!TextUtils.isEmpty(info.permission)) {
                permission = new Permission(info.permission);
            }
        }
    }

    public static class Service extends Component {
        public Permission permission;

        private Service(ServiceInfo info) {
            super(info);
            if (!TextUtils.isEmpty(info.permission)) {
                permission = new Permission(info.permission);
            }
        }
    }

    public static class Receiver extends Component {
        public Permission permission;

        private Receiver(ActivityInfo info) {
            super(info);
            if (!TextUtils.isEmpty(info.permission)) {
                permission = new Permission(info.permission);
            }
        }
    }

    public static class Provider extends Component {
        public String authority;
        public Permission readPermission;
        public Permission writePermission;
        public List<PatternMatcher> uriPermissionPatterns;
        public List<PathPermission> pathPermissions;

        private Provider(ProviderInfo info) {
            super(info);
            authority = info.authority;
            if (!TextUtils.isEmpty(info.readPermission)) {
                readPermission = new Permission(info.readPermission);
            }
            if (!TextUtils.isEmpty(info.writePermission)) {
                writePermission = new Permission(info.writePermission);
            }
            if (info.uriPermissionPatterns != null) {
                uriPermissionPatterns = new ArrayList<>(info.uriPermissionPatterns.length);
                for (android.os.PatternMatcher uriPermissionPattern : info.uriPermissionPatterns) {
                    uriPermissionPatterns.add(new PatternMatcher(uriPermissionPattern));
                }
            }
            if (info.pathPermissions != null) {
                pathPermissions = new ArrayList<>(info.pathPermissions.length);
                for (android.content.pm.PathPermission pathPermission : info.pathPermissions) {
                    pathPermissions.add(new PathPermission(pathPermission));
                }
            }
        }

        public static class PatternMatcher {
            public String path;
            public Type type;

            private PatternMatcher(android.os.PatternMatcher patternMatcher) {
                path = patternMatcher.getPath();
                type = Type.from(patternMatcher.getType());
            }

            public enum Type {
                literal,
                prefix,
                simpleGlob,
                advancedGlob;

                public static Type from(int type) {
                    switch (type) {
                        case android.os.PatternMatcher.PATTERN_LITERAL:
                            return Type.literal;
                        case android.os.PatternMatcher.PATTERN_PREFIX:
                            return Type.prefix;
                        case android.os.PatternMatcher.PATTERN_SIMPLE_GLOB:
                            return Type.simpleGlob;
                        case android.os.PatternMatcher.PATTERN_ADVANCED_GLOB:
                            return Type.advancedGlob;
                        default:
                            return Type.literal;
                    }
                }
            }
        }

        public static class PathPermission extends PatternMatcher {
            public Permission readPermission;
            public Permission writePermission;

            private PathPermission(android.content.pm.PathPermission pathPermission) {
                super(pathPermission);
                readPermission = new Permission(pathPermission.getReadPermission());
                writePermission = new Permission(pathPermission.getWritePermission());
            }
        }
    }

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

    public List<Permission> permissions;
    public List<Activity> activities;
    public List<Service> services;
    public List<Receiver> receivers;
    public List<Provider> providers;

    public Package(PackageInfo info) {
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
                permissions.add(new Permission(p));
            }
        }

        if (info.activities != null) {
            activities = new ArrayList<>(info.activities.length);
            for (ActivityInfo a : info.activities) {
                activities.add(new Activity(a));
            }
        }

        if (info.services != null) {
            services = new ArrayList<>(info.services.length);
            for (ServiceInfo s : info.services) {
                services.add(new Service(s));
            }
        }

        if (info.receivers != null) {
            receivers = new ArrayList<>(info.receivers.length);
            for (ActivityInfo r : info.receivers) {
                receivers.add(new Receiver(r));
            }
        }

        if (info.providers != null) {
            providers = new ArrayList<>(info.providers.length);
            for (ProviderInfo p : info.providers) {
                providers.add(new Provider(p));
            }
        }
    }

}
