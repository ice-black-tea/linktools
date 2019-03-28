/**
 *  该文件用于内置frida脚本的方法，不允许使用"//"对代码进行注释
 *
 *  frida class
 *  └┬─ $classWrapper
 *   │  └─ className
 *   ├─ $getClassHandle
 *   ├─ constructor
 *   ├─ $dispose
 *   └─ $isSameObject
 *
 *  method class
 *  └┬─ methodName
 *   ├─ holder
 *   │  └─ className
 *   ├─ type
 *   ├─ handle
 *   ├─ implementation
 *   ├─ returnType
 *   ├─ argumentTypes
 *   └─ canInvokeWith
 */

var JavaClass = null;
var JavaString = null;
var Throwable = null;
Java.perform(function () {
    JavaClass = Java.use("java.lang.Class");
    JavaString = Java.use("java.lang.String");
    Throwable = Java.use("java.lang.Throwable");
});


/**
 * hook类的所有重载方法
 * :param method:       java方法
 * :return:             java方法名
 */
function getMethodName(method) {
    var name = method.returnType.className + " ";
    name = name + method.holder.className + ".";
    name = name + method.methodName + "(";
    if (method.argumentTypes.length > 0) {
        name = name + method.argumentTypes[0].className;
        for (var i = 1; i < method.argumentTypes.length; i++) {
            name = name + ", " + method.argumentTypes[i].className;
        }
    }
    return name + ")";
}


function findClass(classloader, className) {
    var clazz = null;
    if (classloader != null) {
        var originClassloader = Java.classFactory.loader;
        Java.classFactory.loader = classloader;
        clazz = Java.use(clazz);
        Java.classFactory.loader = originClassloader;
    } else {
        clazz = Java.use(className);
    }
    return clazz;
}


/**
 * 返回hook回调函数，仅用于显示栈和参数
 * :param stack:        是否显示栈（默认为true）
 * :param args:         是否显示参数（默认为true）
 */
function getHookFn(showStack, showArgs) {
    return function(method, obj, args) {
        var ret = method.apply(obj, args);
        if (showStack !== false)
            printStack(method);
        if (showArgs !== false)
            printArgsAndReturn(method, args, ret);
        return ret;
    };
}


/**
 * hook类的所有重载方法
 * :param clazz:        hook的类名
 * :param methodName:   hook的方法名
 * :param fn:           hook后的方法
 */
function hookMethods(clazz, methodName, fn) {
    function hookMethod(method, fn) {
        send("Hook method: " + getMethodName(method));
        method.implementation = function() {
            return fn(method, this, arguments);
        }
    }

    if (typeof(clazz) === "string") {
        clazz = findClass(null, clazz);
    }

    var methods = clazz[methodName].overloads;
    for (var i = 0; i < methods.length; i++) {
        hookMethod(methods[i], fn);
    }
}


/**
 * hook类的所有重载方法
 * :param className:    hook的类名
 * :param fn:           hook后的方法
 */
function hookClass(clazz, fn) {
    if (typeof(clazz) === "string") {
        clazz = findClass(null, clazz);
    }

    /* hook constructs */
    hookMethods(clazz, "$init", fn);

    /* hook methods */
    var methodNames = [];
    var targetClass = clazz.class;
    while (targetClass != null && targetClass.getName() != "java.lang.Object") {
        targetClass.getDeclaredMethods().forEach(function(method) {
            var methodName = method.getName();
            if (methodNames.indexOf(methodName) < 0) {
                methodNames.push(methodName);
                hookMethods(clazz, methodName, fn);
            }
        });
        targetClass = Java.cast(targetClass.getSuperclass(), JavaClass);
    }
}


/**
 * byte数组转字符串，如果转不了就返回null
 * :param bytes:       字符数组
 * :param charset:     字符集(可选)
 */
/*
function BytesToString(bytes, charset) {
    if (bytes === undefined || bytes == null) {
        return null;
    }
    try {
        charset = charset || Charset.defaultCharset();
        return JavaString.$new
            .overload("[B", "java.nio.charset.Charset")
            .call(JavaString, bytes, charset).toString();
    } catch(e) {
        return null;
    }
}
*/


/**
 * 输出当前调用堆栈
 * :param method:       hook的java方法
 */
function printStack(method) {
    var methodName = "";
    var stackElements = Throwable.$new().getStackTrace();
    if (method === undefined || method === null) {
        methodName = stackElements[0];
    } else {
        methodName = getMethodName(method);
    }
    var body = "Stack: " + methodName;
    for (var i = 0; i < stackElements.length; i++) {
        body += "\n    at " + stackElements[i];
    }
    send({"helper_stack": body});
}


/**
 * 输出当前调用堆栈
 * :param method:       hook的java方法
 * :param args:         java方法参数
 * :param ret:          java方法返回值
 */
function printArgsAndReturn(method, args, ret) {
    var methodName = "";
    if (method === undefined || method === null) {
        methodName = Throwable.$new().getStackTrace()[0];
    } else {
        methodName = getMethodName(method);
    }
    var body = "Method: " + methodName;
    for (var i = 0; i < args.length; i++) {
        body += "\n    Arguments[" + i + "]: " + args[i];
    }
    if (ret !== undefined) {
        body += "\n    Return: " + ret;
    }
    send({"helper_method": body});
}


/**
 * 根据调用栈调用当前函数，并输出参数返回值
 * :param object:       对象(一般直接填this)
 * :param args:         arguments(固定填这个)
 */
function callMethod(object, args) {
    var stackElement = Throwable.$new().getStackTrace()[0];
    var methodArgs = "";
    if (args.length > 0) {
        methodArgs += "args[0]";
        for (var i = 1; i < args.length; i++) {
            methodArgs += ",args[" + i + "]";
        }
    }
    var methodName = stackElement.getMethodName();
    if (methodName == "<init>") {
        methodName = "$init";
    }
    return eval("object." + methodName + "(" + methodArgs + ")");
}