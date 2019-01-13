package org.ironman.framework.util;

import android.content.pm.PackageManager;
import android.content.pm.PermissionInfo;
import android.text.TextUtils;

import org.ironman.framework.JEnvironment;
import org.ironman.framework.bean.JPermission;

/**
 * Created by hu on 18-12-17.
 */

public class PermissionUtil {

    private static final String TAG = PermissionUtil.class.getSimpleName();

    public static JPermission.Protection getProtection(String permission) {
        if (!TextUtils.isEmpty(permission)) {
            try {
                return getProtection(JEnvironment.getPackageManager().getPermissionInfo(permission, -1));
            } catch (PackageManager.NameNotFoundException e) {
                LogUtil.printErrStackTrace(TAG, e, null);
            }
        }
        return JPermission.Protection.normal;
    }

    public static JPermission.Protection getProtection(PermissionInfo permissionInfo) {
        switch (permissionInfo.protectionLevel & PermissionInfo.PROTECTION_MASK_BASE) {
            case PermissionInfo.PROTECTION_DANGEROUS:
                return JPermission.Protection.dangerous;
            case PermissionInfo.PROTECTION_NORMAL:
                return JPermission.Protection.normal;
            case PermissionInfo.PROTECTION_SIGNATURE:
                return JPermission.Protection.signature;
            case PermissionInfo.PROTECTION_SIGNATURE_OR_SYSTEM:
                return JPermission.Protection.signatureOrSystem;
            default:
                return JPermission.Protection.normal;
        }
    }

    public static boolean isDangerousOrNormal(PermissionInfo permissionInfo) {
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

    public static boolean isDangerousOrNormal(String permission) {
        if (!TextUtils.isEmpty(permission)) {
            try {
                PackageManager pm = JEnvironment.getPackageManager();
                return isDangerousOrNormal(pm.getPermissionInfo(permission, -1));
            } catch (PackageManager.NameNotFoundException e) {
                LogUtil.printErrStackTrace(TAG, e, null);
            }
        }
        return true;
    }
}
