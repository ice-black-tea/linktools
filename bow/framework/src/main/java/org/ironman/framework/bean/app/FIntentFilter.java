package org.ironman.framework.bean.app;

import android.content.IntentFilter;
import android.os.Build;
import android.os.PatternMatcher;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

public class FIntentFilter {

    public List<String> actions;
    public List<String> categories;
    public List<String> dataSchemes;
    public List<FPatternMatcher> dataSchemeSpecificParts;
    public List<FIntentFilter.AuthorityEntry> dataAuthorities;
    public List<FPatternMatcher> dataPaths;
    public List<String> dataTypes;

    public FIntentFilter(IntentFilter intent) {
        if (intent.countActions() > 0) {
            actions = new ArrayList<>(intent.countActions());
            Iterator<String> it = intent.actionsIterator();
            while (it.hasNext()) {
                actions.add(it.next());
            }
        }

        if (intent.countCategories() > 0) {
            categories = new ArrayList<>(intent.countCategories());
            Iterator<String> it = intent.categoriesIterator();
            while (it.hasNext()) {
                categories.add(it.next());
            }
        }

        if (intent.countDataSchemes() > 0) {
            dataSchemes = new ArrayList<>(intent.countDataSchemes());
            Iterator<String> it = intent.schemesIterator();
            while (it.hasNext()) {
                dataSchemes.add(it.next());
            }
        }

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.KITKAT) {
            if (intent.countDataSchemeSpecificParts() > 0) {
                dataSchemeSpecificParts = new ArrayList<>(intent.countDataSchemeSpecificParts());
                Iterator<PatternMatcher> it = intent.schemeSpecificPartsIterator();
                while (it.hasNext()) {
                    dataSchemeSpecificParts.add(new FPatternMatcher(it.next()));
                }
            }
        }

        if (intent.countDataAuthorities() > 0) {
            dataAuthorities = new ArrayList<>(intent.countDataAuthorities());
            Iterator<IntentFilter.AuthorityEntry> it = intent.authoritiesIterator();
            while (it.hasNext()) {
                dataAuthorities.add(new AuthorityEntry(it.next()));
            }
        }

        if (intent.countDataPaths() > 0) {
            dataPaths = new ArrayList<>(intent.countDataPaths());
            Iterator<PatternMatcher> it = intent.pathsIterator();
            while (it.hasNext()) {
                dataPaths.add(new FPatternMatcher(it.next()));
            }
        }

        if (intent.countDataTypes() > 0) {
            dataTypes = new ArrayList<>(intent.countDataTypes());
            Iterator<String> it = intent.typesIterator();
            while (it.hasNext()) {
                dataTypes.add(it.next());
            }
        }

    }

    public static class AuthorityEntry {

        public String host;
        public int port;

        public AuthorityEntry(IntentFilter.AuthorityEntry authority) {
            host = authority.getHost();
            port = authority.getPort();
        }
    }
}
