package org.ironman.framework.bean;

import android.content.pm.ComponentInfo;

public class JComponent {

    public String name;
    public boolean exported;
    public boolean enabled;

    public JComponent(ComponentInfo info) {
        name = info.name;
        exported = info.exported;
        enabled = info.enabled;
    }
}
