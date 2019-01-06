package org.ironman.framework.bean;

import android.content.pm.ActivityInfo;
import android.text.TextUtils;

public class JActivity extends JComponent {

    public JPermission permission;

    public JActivity(ActivityInfo info) {
        super(info);
        if (!TextUtils.isEmpty(info.permission)) {
            permission = new JPermission(info.permission);
        }
    }
}
