package org.ironman.framework.bean;

import android.content.pm.ActivityInfo;
import android.content.pm.PackageParser;
import android.text.TextUtils;

public class JActivity extends JComponent {

    public JPermission permission;

    public JActivity(PackageParser.Activity activity) {
        super(activity, activity.info);
        if (!TextUtils.isEmpty(activity.info.permission)) {
            permission = new JPermission(activity.info.permission);
        }
    }
}
