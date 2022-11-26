package org.ironman.framework.bean.app;

import android.content.pm.PathPermission;

public class FPathPermission extends FPatternMatcher {

    public FPermission readPermission;
    public FPermission writePermission;

    public FPathPermission(PathPermission pathPermission) {
        super(pathPermission);
        readPermission = new FPermission(pathPermission.getReadPermission());
        writePermission = new FPermission(pathPermission.getWritePermission());
    }
}