package org.ironman.framework.bean;

import android.content.pm.PackageParser;
import android.content.pm.PermissionInfo;

import org.ironman.framework.util.PermissionUtil;

public class JPermission {

    public enum Protection {
        dangerous,
        normal,
        signature,
        signatureOrSystem,
    }

    public String name;
    public Protection protection;

    public JPermission(String name) {
        this.name = name;
        this.protection = PermissionUtil.getProtection(name);
    }

    public JPermission(PackageParser.Permission perm) {
        this.name = perm.info.name;
        this.protection = PermissionUtil.getProtection(perm.info);
    }
}
