package org.ironman.framework.bean.app;

import android.content.pm.PathPermission;

public class JPathPermission extends JPatternMatcher {

    public JPermission readPermission;
    public JPermission writePermission;

    public JPathPermission(PathPermission pathPermission) {
        super(pathPermission);
        readPermission = new JPermission(pathPermission.getReadPermission());
        writePermission = new JPermission(pathPermission.getWritePermission());
    }
}