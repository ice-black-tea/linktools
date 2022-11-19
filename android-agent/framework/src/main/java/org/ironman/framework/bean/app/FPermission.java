package org.ironman.framework.bean.app;

import android.content.pm.PackageParser;

import org.ironman.framework.util.PermissionUtil;

public class FPermission {

    public enum Protection {
        dangerous,
        normal,
        signature,
        signatureOrSystem,
    }

    public String name;
    public Protection protection;

    public FPermission(String name) {
        this.name = name;
        this.protection = PermissionUtil.getProtection(name);
    }

    public FPermission(PackageParser.Permission perm) {
        this.name = perm.info.name;
        this.protection = PermissionUtil.getProtection(perm.info);
    }
}
