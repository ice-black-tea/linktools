package org.ironman.framework.bean;

import android.content.ComponentName;
import android.content.pm.ComponentInfo;
import android.content.pm.PackageParser;

import java.util.ArrayList;
import java.util.List;

public class JComponent<II extends PackageParser.IntentInfo> {

    public String name;
    public boolean exported;
    public boolean enabled;
    public List<JIntentFilter> intents;

    public JComponent(PackageParser.Component<II> component, ComponentInfo info) {
        name = new ComponentName(info.packageName, info.name).flattenToShortString();
        exported = info.exported;
        enabled = info.enabled;

        if (component.intents != null && component.intents.size() > 0) {
            intents = new ArrayList<>(component.intents.size());
            for (II intent : component.intents) {
                intents.add(new JIntentFilter(intent));
            }
        }
    }
}
