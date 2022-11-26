package org.ironman.framework.util;

import com.google.gson.Gson;

import java.lang.reflect.Type;

public class GsonUtil {

    private final static Gson gson = new Gson();

    public static String toJson(Object src) {
        return gson.toJson(src);
    }

    public String toJson(Object src, Type typeOfSrc) {
        return gson.toJson(src, typeOfSrc);
    }
}
