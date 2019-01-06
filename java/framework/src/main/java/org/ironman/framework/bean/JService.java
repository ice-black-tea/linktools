package org.ironman.framework.bean;

import android.content.pm.ServiceInfo;
import android.text.TextUtils;

public class JService extends JComponent {

    public JPermission permission;

    public JService(ServiceInfo info) {
        super(info);
        if (!TextUtils.isEmpty(info.permission)) {
            permission = new JPermission(info.permission);
        }
    }
}
