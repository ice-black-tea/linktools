package org.ironman.framework.bean;

import android.content.pm.ProviderInfo;
import android.text.TextUtils;

import java.util.ArrayList;
import java.util.List;

public class JProvider extends JComponent {

    public String authority;
    public JPermission readPermission;
    public JPermission writePermission;
    public List<JPatternMatcher> uriPermissionPatterns;
    public List<JPathPermission> pathPermissions;

    public JProvider(ProviderInfo info) {
        super(info);
        authority = info.authority;
        if (!TextUtils.isEmpty(info.readPermission)) {
            readPermission = new JPermission(info.readPermission);
        }
        if (!TextUtils.isEmpty(info.writePermission)) {
            writePermission = new JPermission(info.writePermission);
        }
        if (info.uriPermissionPatterns != null) {
            uriPermissionPatterns = new ArrayList<>(info.uriPermissionPatterns.length);
            for (android.os.PatternMatcher uriPermissionPattern : info.uriPermissionPatterns) {
                uriPermissionPatterns.add(new JPatternMatcher(uriPermissionPattern));
            }
        }
        if (info.pathPermissions != null) {
            pathPermissions = new ArrayList<>(info.pathPermissions.length);
            for (android.content.pm.PathPermission pathPermission : info.pathPermissions) {
                pathPermissions.add(new JPathPermission(pathPermission));
            }
        }
    }
}
