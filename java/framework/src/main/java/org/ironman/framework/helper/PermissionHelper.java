package org.ironman.framework.helper;

import android.annotation.SuppressLint;
import android.content.pm.PackageManager;
import android.content.pm.PermissionInfo;
import android.text.TextUtils;

import org.ironman.framework.AtEnvironment;

/**
 * Created by hu on 18-12-17.
 */

public class PermissionHelper {

    @SuppressLint("StaticFieldLeak")
    private static PermissionHelper sInstance = new PermissionHelper();

    public static PermissionHelper get() {
        return sInstance;
    }

    private PermissionHelper() {

    }

    public boolean isDangerousOrNormal(PermissionInfo permissionInfo) {
        switch (permissionInfo.protectionLevel & PermissionInfo.PROTECTION_MASK_BASE) {
            case PermissionInfo.PROTECTION_DANGEROUS:
                return true;
            case PermissionInfo.PROTECTION_NORMAL:
                return true;
            case PermissionInfo.PROTECTION_SIGNATURE:
                return false;
            case PermissionInfo.PROTECTION_SIGNATURE_OR_SYSTEM:
                return false;
            default:
                return true;
        }
    }

    public boolean isDangerousOrNormal(String permission) {
        if (TextUtils.isEmpty(permission)) {
            return true;
        }
        PackageManager pm = AtEnvironment.getPackageManager();
        try {
            return isDangerousOrNormal(pm.getPermissionInfo(permission, -1));
        } catch (PackageManager.NameNotFoundException e) {
            // e.printStackTrace();
        }
        return true;
    }
}
