package org.ironman.framework.bean.app;

import android.content.pm.PackageParser;
import android.text.TextUtils;

@SuppressWarnings({"rawtypes", "unchecked"})
public class FService extends FComponent {

    public FPermission permission;

    public FService(PackageParser.Service service) {
        super(service, service.info);
        if (!TextUtils.isEmpty(service.info.permission)) {
            permission = new FPermission(service.info.permission);
        }
    }
}
