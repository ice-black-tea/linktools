package org.ironman.framework.bean;

import android.content.pm.PackageParser;
import android.text.TextUtils;

import java.util.ArrayList;
import java.util.List;

public class JProvider extends JComponent {

    public String authority;
    public JPermission readPermission;
    public JPermission writePermission;
    public List<JPatternMatcher> uriPermissionPatterns;
    public List<JPathPermission> pathPermissions;

    public JProvider(PackageParser.Provider provider) {
        super(provider, provider.info);

        authority = provider.info.authority;
        if (!TextUtils.isEmpty(provider.info.readPermission)) {
            readPermission = new JPermission(provider.info.readPermission);
        }
        if (!TextUtils.isEmpty(provider.info.writePermission)) {
            writePermission = new JPermission(provider.info.writePermission);
        }
        if (provider.info.uriPermissionPatterns != null) {
            uriPermissionPatterns = new ArrayList<>(provider.info.uriPermissionPatterns.length);
            for (android.os.PatternMatcher uriPermissionPattern : provider.info.uriPermissionPatterns) {
                uriPermissionPatterns.add(new JPatternMatcher(uriPermissionPattern));
            }
        }
        if (provider.info.pathPermissions != null) {
            pathPermissions = new ArrayList<>(provider.info.pathPermissions.length);
            for (android.content.pm.PathPermission pathPermission : provider.info.pathPermissions) {
                pathPermissions.add(new JPathPermission(pathPermission));
            }
        }
    }
}
