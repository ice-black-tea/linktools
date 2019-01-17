package org.ironman.framework.util;

import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.NoSuchElementException;

/**
 * Created by HuJi on 2017/12/29.
 */

public class ReflectUtil {

    public static ClassLoader getClassLoader() {
        return Thread.currentThread().getContextClassLoader();
    }

    public static Class<?> loadClass(String className)
            throws ClassNotFoundException {
        switch (className) {
            case "boolean": return boolean.class;
            case "byte": return byte.class;
            case "char": return char.class;
            case "short": return short.class;
            case "int": return int.class;
            case "long": return long.class;
            case "float": return float.class;
            case "double": return double.class;
            case "void": return void.class;
        }
        return Class.forName(className, true, getClassLoader());
    }

    public static Class<?> wrapClass(Class<?> clazz) {
        switch (clazz.getName()) {
            case "boolean": return Boolean.class;
            case "byte": return Byte.class;
            case "char": return Character.class;
            case "short": return Short.class;
            case "int": return Integer.class;
            case "long": return Long.class;
            case "float": return Float.class;
            case "double": return Double.class;
            case "void": return Void.class;
        }
        return clazz;
    }

    public static <T> Method findMethod(String className, String methodName, T... args)
            throws ClassNotFoundException, NoSuchMethodException {
        return findMethod(loadClass(className), methodName, args);
    }

    public static <T> Method findMethod(Class<?> clazz, String methodName, T... args)
            throws NoSuchMethodException {
        Class<?> tmp = clazz;
        for (; tmp != null; tmp = tmp.getSuperclass()) {
            Method[] methods = tmp.getDeclaredMethods();
            for (Method method : methods) {
                if (methodName.equals(method.getName()) && equalParams(method, args)) {
                    return method;
                }
            }
        }
        throw new NoSuchElementException(clazz.getName() + "." + methodName + "()");
    }

    public static boolean equalParams(Method method, Object... params) {
        return equalParams(method.getParameterTypes(), params);
    }

    public static boolean equalParams(Class<?>[] parameterTypes, Object... params) {
        if (parameterTypes.length != params.length) {
            return false;
        }
        for (int i = 0; i < parameterTypes.length; i++) {
            if (parameterTypes[i].isPrimitive()) {
                if (params[i] == null || !wrapClass(parameterTypes[i]).equals(params[i].getClass())) {
                    return false;
                }
            } else {
                if (params[i] != null && !parameterTypes[i].isAssignableFrom(params[i].getClass())) {
                    return false;
                }
            }
        }
        return true;
    }

    public static boolean equalParams(Method method, Class<?>... types) {
        return equalParams(method.getParameterTypes(), types);
    }

    public static boolean equalParams(Class<?>[] parameterTypes, Class<?>... types) {
        if (parameterTypes.length != types.length) {
            return false;
        }
        for (int i = 0; i < parameterTypes.length; i++) {
            if (parameterTypes[i].isAssignableFrom(types[i])) {
                return false;
            }
        }
        return true;
    }

    public static <T> Method getMethod(String className, String methodName, T... parameterTypes)
            throws ClassNotFoundException, NoSuchMethodException {
        return getMethod(loadClass(className), methodName, getClassType(parameterTypes));
    }

    public static Method getMethod(String className, String methodName, Class<?>... parameterTypes)
            throws ClassNotFoundException, NoSuchMethodException {
        return getMethod(loadClass(className), methodName, parameterTypes);
    }

    public static <T> Method getMethod(Class<?> clazz, String methodName, T... parameterTypes)
            throws ClassNotFoundException, NoSuchMethodException {
        return getMethod(clazz, methodName, getClassType(parameterTypes));
    }

    public static Method getMethod(Class<?> clazz, String methodName, Class<?>... parameterTypes)
            throws NoSuchMethodException {
        NoSuchMethodException exception = null;
        for (; clazz != null; clazz = clazz.getSuperclass()) {
            try {
                Method method = clazz.getDeclaredMethod(methodName, parameterTypes);
                if (!method.isAccessible()) {
                    method.setAccessible(true);
                }
                return method;
            } catch (NoSuchMethodException e) {
                if (exception == null) {
                    exception = e;
                }
            }
        }
        throw exception;
    }

    @SuppressWarnings("unchecked")
    public static <T> T invoke(String className, String methodName)
            throws InvocationTargetException, IllegalAccessException, ClassNotFoundException, NoSuchMethodException {
        return (T) getMethod(loadClass(className), methodName).invoke(null);
    }

    @SuppressWarnings("unchecked")
    public static <T> T invoke(Class<?> clazz, String methodName)
            throws InvocationTargetException, IllegalAccessException, ClassNotFoundException, NoSuchMethodException {
        return (T) getMethod(clazz, methodName).invoke(null);
    }

    @SuppressWarnings("unchecked")
    public static <T> T invoke(Object object, String methodName)
            throws InvocationTargetException, IllegalAccessException, ClassNotFoundException, NoSuchMethodException {
        return (T) getMethod(object.getClass(), methodName).invoke(object);
    }

    @SuppressWarnings("unchecked")
    public static <T> T  invoke(String className, String methodName, Object... parameterTypesAndParameters)
            throws InvocationTargetException, IllegalAccessException, ClassNotFoundException, NoSuchMethodException {
        int length = parameterTypesAndParameters.length;
        Class<?>[] parameterTypes = getClassType(parameterTypesAndParameters, 0, length >> 1);
        Object[] parameters = getParameters(parameterTypesAndParameters, length >> 1, length >> 1);
        return (T) getMethod(loadClass(className), methodName, parameterTypes).invoke(null, parameters);
    }

    @SuppressWarnings("unchecked")
    public static <T> T invoke(Class<?> clazz, String methodName, Object... parameterTypesAndParameters)
            throws InvocationTargetException, IllegalAccessException, ClassNotFoundException, NoSuchMethodException {
        int length = parameterTypesAndParameters.length;
        Class<?>[] parameterTypes = getClassType(parameterTypesAndParameters, 0, length >> 1);
        Object[] parameters = getParameters(parameterTypesAndParameters, length >> 1, length >> 1);
        return (T) getMethod(clazz, methodName, parameterTypes).invoke(null, parameters);
    }

    @SuppressWarnings("unchecked")
    public static <T> T invoke(Object object, String methodName, Object... parameterTypesAndParameters)
            throws InvocationTargetException, IllegalAccessException, ClassNotFoundException, NoSuchMethodException {
        int length = parameterTypesAndParameters.length;
        Class<?>[] parameterTypes = getClassType(parameterTypesAndParameters, 0, length >> 1);
        Object[] parameters = getParameters(parameterTypesAndParameters, length >> 1, length >> 1);
        return (T) getMethod(object.getClass(), methodName, parameterTypes).invoke(object, parameters);
    }

    public static Constructor<?> getConstructor(String className, Object... parameterTypes)
            throws ClassNotFoundException, NoSuchMethodException {
        return getConstructor(loadClass(className), getClassType(parameterTypes));
    }

    public static Constructor<?> getConstructor(String className, Class<?>... parameterTypes)
            throws ClassNotFoundException, NoSuchMethodException {
        return getConstructor(loadClass(className), parameterTypes);
    }

    public static <T> Constructor<?> getConstructor(Class<?> clazz, T... parameterTypes)
            throws ClassNotFoundException, NoSuchMethodException {
        return getConstructor(clazz, getClassType(parameterTypes));
    }

    public static Constructor<?> getConstructor(Class<?> clazz, Class<?>... parameterTypes)
            throws ClassNotFoundException, NoSuchMethodException {
        Constructor constructor = clazz.getConstructor(parameterTypes);
        if (!constructor.isAccessible()) {
            constructor.setAccessible(true);
        }
        return constructor;
    }

    @SuppressWarnings("unchecked")
    public static <T> T newInstance(String className)
            throws ClassNotFoundException, NoSuchMethodException, IllegalAccessException,
            InvocationTargetException, InstantiationException {
        return (T) getConstructor(loadClass(className)).newInstance();
    }

    @SuppressWarnings("unchecked")
    public static <T> T newInstance(Class clazz)
            throws ClassNotFoundException, NoSuchMethodException, IllegalAccessException,
            InvocationTargetException, InstantiationException {
        return (T) getConstructor(clazz).newInstance();
    }

    @SuppressWarnings("unchecked")
    public static <T> T newInstance(String className, Object... parameterTypesAndParameters)
            throws ClassNotFoundException, NoSuchMethodException, IllegalAccessException,
            InvocationTargetException, InstantiationException {
        int length = parameterTypesAndParameters.length;
        Class<?>[] parameterTypes = getClassType(parameterTypesAndParameters, 0, length >> 1);
        Object[] parameters = getParameters(parameterTypesAndParameters, length >> 1, length >> 1);
        return (T) getConstructor(loadClass(className), parameterTypes).newInstance(parameters);
    }

    @SuppressWarnings("unchecked")
    public static <T> T newInstance(Class clazz, Object... parameterTypesAndParameters)
            throws ClassNotFoundException, NoSuchMethodException, IllegalAccessException,
            InvocationTargetException, InstantiationException {
        int length = parameterTypesAndParameters.length;
        Class<?>[] parameterTypes = getClassType(parameterTypesAndParameters, 0, length >> 1);
        Object[] parameters = getParameters(parameterTypesAndParameters, length >> 1, length >> 1);
        return (T) getConstructor(clazz, parameterTypes).newInstance(parameters);
    }

    private static <T> Class<?>[] getClassType(T... parameterTypes)
            throws ClassNotFoundException {
        Class<?>[] type = new Class[parameterTypes != null ? parameterTypes.length : 0];
        for (int i = 0; i < type.length; i++) {
            if (parameterTypes[i] instanceof Class<?>) {
                type[i] = (Class<?>) parameterTypes[i];
            } else if (parameterTypes[i] instanceof String) {
                type[i] = loadClass((String) parameterTypes[i]);
            } else {
                type[i] = parameterTypes[i].getClass();
            }
        }
        return type;
    }

    private static Class<?>[] getClassType(Object[] parameterTypes, int offset, int length)
            throws ClassNotFoundException {
        Class<?>[] type = new Class[length];
        for (int i = offset; i < offset + length; i++) {
            if (parameterTypes[i] instanceof Class<?>) {
                type[i] = (Class<?>) parameterTypes[i];
            } else if (parameterTypes[i] instanceof String) {
                type[i] = loadClass((String) parameterTypes[i]);
            } else {
                type[i] = parameterTypes[i].getClass();
            }
        }
        return type;
    }

    private static Object[] getParameters(Object[] parameters, int offset, int length) {
        Object[] params = new Object[length];
        System.arraycopy(parameters, offset, params, 0, length);
        return params;
    }

    public static Field getField(Object object, String fieldName)
            throws NoSuchFieldException {
        return getField(object.getClass(), fieldName);
    }

    public static Field getField(Class<?> clazz, String fieldName)
            throws NoSuchFieldException {
        NoSuchFieldException exception = null;
        for (; clazz != null; clazz = clazz.getSuperclass()) {
            try {
                Field field = clazz.getDeclaredField(fieldName);
                if (!field.isAccessible()) {
                    field.setAccessible(true);
                }
                return field;
            } catch (NoSuchFieldException e) {
                if (exception == null) {
                    exception = e;
                }
            }
        }
        //noinspection ConstantConditions
        throw exception;
    }

    @SuppressWarnings("unchecked")
    public static <T> T  get(String className, String fieldName)
            throws ClassNotFoundException, NoSuchFieldException, IllegalAccessException {
        return (T) getField(loadClass(className), fieldName).get(null);
    }

    @SuppressWarnings("unchecked")
    public static <T> T  get(Class<?> clazz, String fieldName)
            throws NoSuchFieldException, IllegalAccessException {
        return (T) getField(clazz, fieldName).get(null);
    }

    @SuppressWarnings("unchecked")
    public static <T> T  get(Object object, String fieldName)
            throws NoSuchFieldException, IllegalAccessException {
        return (T) getField(object.getClass(), fieldName).get(object);
    }

    public static void set(String className, String fieldName, Object value)
            throws NoSuchFieldException, IllegalAccessException, ClassNotFoundException {
        getField(loadClass(className), fieldName).set(null, value);
    }

    public static void set(Class<?> clazz, String fieldName, Object value)
            throws NoSuchFieldException, IllegalAccessException {
        getField(clazz, fieldName).set(null, value);
    }

    public static void set(Object object, String fieldName, Object value)
            throws NoSuchFieldException, IllegalAccessException {
        getField(object.getClass(), fieldName).set(object, value);
    }

    public static boolean getBoolean(String className, String fieldName)
            throws ClassNotFoundException, NoSuchFieldException, IllegalAccessException {
        return getField(loadClass(className), fieldName).getBoolean(null);
    }

    public static boolean getBoolean(Class<?> clazz, String fieldName)
            throws NoSuchFieldException, IllegalAccessException {
        return getField(clazz, fieldName).getBoolean(null);
    }

    public static boolean getBoolean(Object object, String fieldName)
            throws NoSuchFieldException, IllegalAccessException {
        return getField(object.getClass(), fieldName).getBoolean(object);
    }

    public static void setBoolean(String className, String fieldName, boolean value)
            throws NoSuchFieldException, IllegalAccessException, ClassNotFoundException {
        getField(loadClass(className), fieldName).setBoolean(null, value);
    }

    public static void setBoolean(Class<?> clazz, String fieldName, boolean value)
            throws NoSuchFieldException, IllegalAccessException {
        getField(clazz, fieldName).setBoolean(null, value);
    }

    public static void setBoolean(Object object, String fieldName, boolean value)
            throws NoSuchFieldException, IllegalAccessException {
        getField(object.getClass(), fieldName).setBoolean(object, value);
    }

    public static byte getByte(String className, String fieldName)
            throws ClassNotFoundException, NoSuchFieldException, IllegalAccessException {
        return getField(loadClass(className), fieldName).getByte(null);
    }

    public static byte getByten(Class<?> clazz, String fieldName)
            throws NoSuchFieldException, IllegalAccessException {
        return getField(clazz, fieldName).getByte(null);
    }

    public static byte getByte(Object object, String fieldName)
            throws NoSuchFieldException, IllegalAccessException {
        return getField(object.getClass(), fieldName).getByte(object);
    }

    public static void setBoolean(String className, String fieldName, byte value)
            throws NoSuchFieldException, IllegalAccessException, ClassNotFoundException {
        getField(loadClass(className), fieldName).setByte(null, value);
    }

    public static void setBoolean(Class<?> clazz, String fieldName, byte value)
            throws NoSuchFieldException, IllegalAccessException {
        getField(clazz, fieldName).setByte(null, value);
    }

    public static void setByte(Object object, String fieldName, byte value)
            throws NoSuchFieldException, IllegalAccessException {
        getField(object.getClass(), fieldName).setByte(object, value);
    }

    public static char getChar(String className, String fieldName)
            throws ClassNotFoundException, NoSuchFieldException, IllegalAccessException {
        return getField(loadClass(className), fieldName).getChar(null);
    }

    public static char getChar(Class<?> clazz, String fieldName)
            throws NoSuchFieldException, IllegalAccessException {
        return getField(clazz, fieldName).getChar(null);
    }

    public static char getChar(Object object, String fieldName)
            throws NoSuchFieldException, IllegalAccessException {
        return getField(object.getClass(), fieldName).getChar(object);
    }

    public static void setBoolean(String className, String fieldName, char value)
            throws NoSuchFieldException, IllegalAccessException, ClassNotFoundException {
        getField(loadClass(className), fieldName).setChar(null, value);
    }

    public static void setBoolean(Class<?> clazz, String fieldName, char value)
            throws NoSuchFieldException, IllegalAccessException {
        getField(clazz, fieldName).setChar(null, value);
    }

    public static void setChar(Object object, String fieldName, char value)
            throws NoSuchFieldException, IllegalAccessException {
        getField(object.getClass(), fieldName).setChar(object, value);
    }

    public static short getShort(String className, String fieldName)
            throws ClassNotFoundException, NoSuchFieldException, IllegalAccessException {
        return getField(loadClass(className), fieldName).getShort(null);
    }

    public static short getShort(Class<?> clazz, String fieldName)
            throws NoSuchFieldException, IllegalAccessException {
        return getField(clazz, fieldName).getShort(null);
    }

    public static short getShort(Object object, String fieldName)
            throws NoSuchFieldException, IllegalAccessException {
        return getField(object.getClass(), fieldName).getShort(object);
    }

    public static void setShort(String className, String fieldName, short value)
            throws NoSuchFieldException, IllegalAccessException, ClassNotFoundException {
        getField(loadClass(className), fieldName).setShort(null, value);
    }

    public static void setShort(Class<?> clazz, String fieldName, short value)
            throws NoSuchFieldException, IllegalAccessException {
        getField(clazz, fieldName).setShort(null, value);
    }

    public static void setShort(Object object, String fieldName, short value)
            throws NoSuchFieldException, IllegalAccessException {
        getField(object.getClass(), fieldName).setShort(object, value);
    }

    public static int getInt(String className, String fieldName)
            throws ClassNotFoundException, NoSuchFieldException, IllegalAccessException {
        return getField(loadClass(className), fieldName).getInt(null);
    }

    public static int getInt(Class<?> clazz, String fieldName)
            throws NoSuchFieldException, IllegalAccessException {
        return getField(clazz, fieldName).getInt(null);
    }

    public static int getInt(Object object, String fieldName)
            throws NoSuchFieldException, IllegalAccessException {
        return getField(object.getClass(), fieldName).getInt(object);
    }

    public static void setInt(String className, String fieldName, int value)
            throws NoSuchFieldException, IllegalAccessException, ClassNotFoundException {
        getField(loadClass(className), fieldName).setInt(null, value);
    }

    public static void setInt(Class<?> clazz, String fieldName, int value)
            throws NoSuchFieldException, IllegalAccessException {
        getField(clazz, fieldName).setInt(null, value);
    }

    public static void setInt(Object object, String fieldName, int value)
            throws NoSuchFieldException, IllegalAccessException {
        getField(object.getClass(), fieldName).setInt(object, value);
    }

    public static long getLong(String className, String fieldName)
            throws ClassNotFoundException, NoSuchFieldException, IllegalAccessException {
        return getField(loadClass(className), fieldName).getLong(null);
    }

    public static long getLong(Class<?> clazz, String fieldName)
            throws NoSuchFieldException, IllegalAccessException {
        return getField(clazz, fieldName).getLong(null);
    }

    public static long getLong(Object object, String fieldName)
            throws NoSuchFieldException, IllegalAccessException {
        return getField(object.getClass(), fieldName).getLong(object);
    }

    public static void setLong(String className, String fieldName, long value)
            throws NoSuchFieldException, IllegalAccessException, ClassNotFoundException {
        getField(loadClass(className), fieldName).setLong(null, value);
    }

    public static void setLong(Class<?> clazz, String fieldName, long value)
            throws NoSuchFieldException, IllegalAccessException {
        getField(clazz, fieldName).setLong(null, value);
    }

    public static void setLong(Object object, String fieldName, long value)
            throws NoSuchFieldException, IllegalAccessException {
        getField(object.getClass(), fieldName).setLong(object, value);
    }

    public static float getFloat(String className, String fieldName)
            throws ClassNotFoundException, NoSuchFieldException, IllegalAccessException {
        return getField(loadClass(className), fieldName).getFloat(null);
    }

    public static float getFloat(Class<?> clazz, String fieldName)
            throws NoSuchFieldException, IllegalAccessException {
        return getField(clazz, fieldName).getFloat(null);
    }

    public static float getFloat(Object object, String fieldName)
            throws NoSuchFieldException, IllegalAccessException {
        return getField(object.getClass(), fieldName).getFloat(object);
    }

    public static void setFloat(String className, String fieldName, float value)
            throws NoSuchFieldException, IllegalAccessException, ClassNotFoundException {
        getField(loadClass(className), fieldName).setFloat(null, value);
    }

    public static void setFloat(Class<?> clazz, String fieldName, float value)
            throws NoSuchFieldException, IllegalAccessException {
        getField(clazz, fieldName).setFloat(null, value);
    }

    public static void setFloat(Object object, String fieldName, float value)
            throws NoSuchFieldException, IllegalAccessException {
        getField(object.getClass(), fieldName).setFloat(object, value);
    }

    public static double getDouble(String className, String fieldName)
            throws ClassNotFoundException, NoSuchFieldException, IllegalAccessException {
        return getField(loadClass(className), fieldName).getDouble(null);
    }

    public static double getDouble(Class<?> clazz, String fieldName)
            throws NoSuchFieldException, IllegalAccessException {
        return getField(clazz, fieldName).getDouble(null);
    }

    public static double getDouble(Object object, String fieldName)
            throws NoSuchFieldException, IllegalAccessException {
        return getField(object.getClass(), fieldName).getDouble(object);
    }

    public static void setDouble(String className, String fieldName, double value)
            throws NoSuchFieldException, IllegalAccessException, ClassNotFoundException {
        getField(loadClass(className), fieldName).setDouble(null, value);
    }

    public static void setDouble(Class<?> clazz, String fieldName, double value)
            throws NoSuchFieldException, IllegalAccessException {
        getField(clazz, fieldName).setDouble(null, value);
    }

    public static void setDouble(Object object, String fieldName, double value)
            throws NoSuchFieldException, IllegalAccessException {
        getField(object.getClass(), fieldName).setDouble(object, value);
    }
}
