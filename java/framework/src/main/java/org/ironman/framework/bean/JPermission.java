package org.ironman.framework.bean;

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

    public JPermission(PermissionInfo info) {
        this.name = info.name;
        this.protection = PermissionUtil.getProtection(info);
    }
}
