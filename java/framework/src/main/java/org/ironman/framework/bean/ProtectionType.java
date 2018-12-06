package org.ironman.framework.bean;

import android.content.pm.PermissionInfo;

/**
 * Created by hu on 18-12-5.
 */

public enum ProtectionType {

    DANGEROUS,
    NORMAL,
    SIGNATURE,
    SIGNATURE_OR_SYSTEM,
    UNKNOWN;

    public static ProtectionType from(PermissionInfo permissionInfo) {
        return from(permissionInfo.protectionLevel);
    }

    public static ProtectionType from(int protectionLevel) {
        switch (protectionLevel & PermissionInfo.PROTECTION_MASK_BASE) {
            case PermissionInfo.PROTECTION_DANGEROUS:
                return DANGEROUS;
            case PermissionInfo.PROTECTION_NORMAL:
                return NORMAL;
            case PermissionInfo.PROTECTION_SIGNATURE:
                return SIGNATURE;
            case PermissionInfo.PROTECTION_SIGNATURE_OR_SYSTEM:
                return SIGNATURE_OR_SYSTEM;
            default:
                return UNKNOWN;
        }
    }
}
