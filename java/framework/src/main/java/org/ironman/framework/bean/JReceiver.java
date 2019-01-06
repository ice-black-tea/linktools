package org.ironman.framework.bean;

import android.content.pm.ActivityInfo;
import android.text.TextUtils;

public class JReceiver extends JComponent {

    public JPermission permission;

    public JReceiver(ActivityInfo info) {
        super(info);
        if (!TextUtils.isEmpty(info.permission)) {
            permission = new JPermission(info.permission);
        }
    }
}
