package org.ironman.framework.bean.app;

import android.content.pm.PackageParser;
import android.text.TextUtils;

@SuppressWarnings({"rawtypes", "unchecked"})
public class FActivity extends FComponent {

    public FPermission permission;

    public FActivity(PackageParser.Activity activity) {
        super(activity, activity.info);
        if (!TextUtils.isEmpty(activity.info.permission)) {
            permission = new FPermission(activity.info.permission);
        }
    }
}
