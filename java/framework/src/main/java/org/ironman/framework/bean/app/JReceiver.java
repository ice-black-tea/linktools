package org.ironman.framework.bean.app;

import android.content.pm.PackageParser;
import android.text.TextUtils;

public class JReceiver extends JComponent {

    public JPermission permission;

    public JReceiver(PackageParser.Activity receiver) {
        super(receiver, receiver.info);
        if (!TextUtils.isEmpty(receiver.info.permission)) {
            permission = new JPermission(receiver.info.permission);
        }
    }
}
