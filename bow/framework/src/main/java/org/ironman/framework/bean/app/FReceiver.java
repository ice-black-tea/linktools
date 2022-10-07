package org.ironman.framework.bean.app;

import android.content.pm.PackageParser;
import android.text.TextUtils;

@SuppressWarnings({"rawtypes", "unchecked"})
public class FReceiver extends FComponent {

    public FPermission permission;

    public FReceiver(PackageParser.Activity receiver) {
        super(receiver, receiver.info);
        if (!TextUtils.isEmpty(receiver.info.permission)) {
            permission = new FPermission(receiver.info.permission);
        }
    }
}
