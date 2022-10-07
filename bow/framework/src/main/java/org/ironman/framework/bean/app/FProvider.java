package org.ironman.framework.bean.app;

import android.content.pm.PackageParser;
import android.text.TextUtils;

import java.util.ArrayList;
import java.util.List;

@SuppressWarnings({"rawtypes", "unchecked"})
public class FProvider extends FComponent {

    public String authority;
    public FPermission readPermission;
    public FPermission writePermission;
    public List<FPatternMatcher> uriPermissionPatterns;
    public List<FPathPermission> pathPermissions;

    public FProvider(PackageParser.Provider provider) {
        super(provider, provider.info);

        authority = provider.info.authority;
        if (!TextUtils.isEmpty(provider.info.readPermission)) {
            readPermission = new FPermission(provider.info.readPermission);
        }
        if (!TextUtils.isEmpty(provider.info.writePermission)) {
            writePermission = new FPermission(provider.info.writePermission);
        }
        if (provider.info.uriPermissionPatterns != null) {
            uriPermissionPatterns = new ArrayList<>(provider.info.uriPermissionPatterns.length);
            for (android.os.PatternMatcher uriPermissionPattern : provider.info.uriPermissionPatterns) {
                uriPermissionPatterns.add(new FPatternMatcher(uriPermissionPattern));
            }
        }
        if (provider.info.pathPermissions != null) {
            pathPermissions = new ArrayList<>(provider.info.pathPermissions.length);
            for (android.content.pm.PathPermission pathPermission : provider.info.pathPermissions) {
                pathPermissions.add(new FPathPermission(pathPermission));
            }
        }
    }
}
