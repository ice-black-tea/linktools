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

function addMethod(object, name, fn) {
    var old = object[name];
    object[name + '_$_$_' + fn.length] = fn;
    object[name] = function () {
        var prop = name + '_$_$_' + arguments.length;
        if (object.hasOwnProperty(prop)) {
            return object[prop].apply(this, arguments);
        } else {
            throw new Error("Argument count of " + arguments.length + " does not match " + name);
        }
    }
}

function JavaHelper() {

    var helper = this;
    var javaClass = Java.use("java.lang.Class");
    var javaString = Java.use("java.lang.String");
    var javaThrowable = Java.use("java.lang.Throwable");

    var primitiveTypes = {
        boolean: { name: 'Z' },
        byte: { name: 'B' },
        char: { name: 'C' },
        short: { name: 'S' },
        int: { name: 'I' },
        long: { name: 'J' },
        float: { name: 'F' },
        double: { name: 'D' },
        void: { name: 'V' },
    };

    /**
     * 获取类对象类名
     * :param clazz:        类对象
     * :return:             类名
     */
    addMethod(this, "getClassName", function(clazz) {
        return clazz.$classWrapper.__name__;
    });

    /**
     * 获取java类的类对象
     * :param className:    java类名
     * :return:             类对象
     */
    addMethod(this, "findClass", function(className) {
        return Java.use(className);
    });

    /**
     * 获取java类的类对象
     * :param classloader:  java类所在的ClassLoader
     * :param className:    java类名
     * :return:             类对象
     */
    addMethod(this, "findClass", function(classloader, className) {
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
    });

    /**
     * 为method添加properties
     * :param method:       方法对象
     */
    addMethod(this, "addMethodProperties", function(method) {
        method.toString = function() {
            var ret = this.returnType.className;
            var name = this.holder.__name__ + "." + this.methodName;
            var args = "";
            if (this.argumentTypes.length > 0) {
                args = this.argumentTypes[0].className;
                for (var i = 1; i < this.argumentTypes.length; i++) {
                    args = args + ", " + this.argumentTypes[i].className;
                }
            }
            return ret + " " + name + "(" + args + ")";
        };
    });

    /**
     * hook指定方法对象
     * :param method:       方法对象
     * :param impl:         hook实现，如调用原函数： function(obj, args) { return this.apply(obj, args); }
     */
    addMethod(this, "hookMethod", function(method, impl) {
        method.implementation = function() {
            return impl.call(method, this, arguments);
        };
        helper.addMethodProperties(method);
        send("Hook method: " + method);
    });

    /**
     * hook指定方法对象
     * :param clazz:        java类名/类对象
     * :param method:       java方法名/方法对象
     * :param impl:         hook实现，如调用原函数： function(obj, args) { return this.apply(obj, args); }
     */
    addMethod(this, "hookMethod", function(clazz, method, impl) {
        helper.hookMethod(clazz, method, null, impl);
    });

    /**
     * hook指定方法对象
     * :param clazz:        java类名/类对象
     * :param method:       java方法名/方法对象
     * :param signature:    java方法签名，为null表示不设置签名
     * :param impl:         hook实现，如调用原函数： function(obj, args) { return this.apply(obj, args); }
     */
    addMethod(this, "hookMethod", function(clazz, method, signature, impl) {
        if (typeof(clazz) === "string") {
            clazz = helper.findClass(null, clazz);
        }
        if (typeof(method) === "string") {
            method = clazz[method];
            if (signature != null) {
                for (var i in signature) {
                    if (typeof(signature[i]) !== "string") {
                        signature[i] = helper.getClassName(signature[i]);
                    }
                }
                method = method.overload.apply(method, signature);
            }
        }
        helper.hookMethod(method, impl);
    });

    /**
     * hook指定方法名的所有重载
     * :param clazz:        java类名/类对象
     * :param method:       java方法名
     * :param impl:         hook实现，如调用原函数： function(obj, args) { return this.apply(obj, args); }
     */
    addMethod(this, "hookMethods", function(clazz, methodName, impl) {
        if (typeof(clazz) === "string") {
            clazz = helper.findClass(null, clazz);
        }
        var methods = clazz[methodName].overloads;
        for (var i = 0; i < methods.length; i++) {
            helper.hookMethod(clazz, methods[i], null, impl);
        }
    });

    /**
     * hook指定类的所有方法
     * :param clazz:        java类名/类对象
     * :param impl:         hook实现，如调用原函数： function(obj, args) { return this.apply(obj, args); }
     */
    addMethod(this, "hookClass", function(clazz, impl) {
        if (typeof(clazz) === "string") {
            clazz = helper.findClass(null, clazz);
        }

        var targetClass = clazz.class;
        var methodNames = [];

        helper.hookMethods(clazz, "$init", impl); /* hook constructor */
        while (targetClass != null && targetClass.getName() != "java.lang.Object") {
            targetClass.getDeclaredMethods().forEach(function(method) {
                var methodName = method.getName();
                if (methodNames.indexOf(methodName) < 0) {
                    methodNames.push(methodName);
                    helper.hookMethods(clazz, methodName, impl); /* hook method */
                }
            });
            targetClass = Java.cast(targetClass.getSuperclass(), javaClass);
        }
    });

    /**
     * 根据当前栈调用原java方法
     * :param obj:          java对象
     * :param args:         java参数
     * :return:             java方法返回值
     */
    addMethod(this, "callMethod", function(obj, args) {
        var methodName = helper.getStackTrace()[0].getMethodName();
        if (methodName == "<init>") {
            methodName = "$init";
        }
        var methodArgs = "";
        if (args.length > 0) {
            methodArgs += "args[0]";
            for (var i = 1; i < args.length; i++) {
                methodArgs += ",args[" + i + "]";
            }
        }
        return eval("obj." + methodName + "(" + methodArgs + ")");
    });

    /**
     * 获取hook实现，调用愿方法并展示栈和返回值
     * :param printStack:   是否展示栈，默认为true
     * :param printArgs:    是否展示参数，默认为true
     * :return:             hook实现
     */
    addMethod(this, "getHookImpl", function(printStack, printArgs) {
        return function(obj, args) {
            var ret = this.apply(obj, args);
            if (printStack !== false)
                helper.printStack(this);
            if (printArgs !== false)
                helper.printArguments(this, args, ret);
            return ret;
        };
    });

    /**
     * java数组转为js数组
     * :param clazz:        java类名/类对象
     * :param array:        java数组
     * :return:             js数组
     */
    addMethod(this, "fromJavaArray", function(clazz, array) {
        if (typeof(clazz) === "string") {
            clazz = helper.findClass(clazz);
        }
        var result = [];
        var env = Java.vm.getEnv();
        for (var i = 0; i < env.getArrayLength(array.$handle); i++) {
            result.push(Java.cast(env.getObjectArrayElement(array.$handle, i), clazz))
        }
        return result;
    });

    /**
     * 获取枚举值
     * :param clazz:        java类名/类对象
     * :param name:         java枚举名称
     * :return:             java枚举值
     */
    addMethod(this, "getEnumValue", function(clazz, name) {
        if (typeof(clazz) === "string") {
            clazz = helper.findClass(clazz);
        }
        var values = helper.fromJavaArray(clazz, clazz.class.getEnumConstants());
        for (var i in values) {
            if (values[i].toString() == name) {
                return values[i];
            }
        }
        throw new Error("Name of " + name + " does not match " + clazz);
    });

    /**
     * 获取当前java栈
     * :param printStack:   是否展示栈，默认为true
     * :param printArgs:    是否展示参数，默认为true
     * :return:             java栈对象
     */
    addMethod(this, "getStackTrace", function() {
        return javaThrowable.$new().getStackTrace();
    });

    function printStack(name, elements) {
        var body = "Stack: " + name;
        for (var i = 0; i < elements.length; i++) {
            body += "\n    at " + elements[i];
        }
        send({"helper_stack": body});
    }

    /**
     * 打印当前栈
     */
    addMethod(this, "printStack", function() {
        var elements = helper.getStackTrace();
        printStack(elements[0], elements);
    });

    /**
     * 打印当前栈
     * :param message:      回显的信息
     */
    addMethod(this, "printStack", function(message) {
        var elements = helper.getStackTrace();
        printStack(message, elements);
    });

    function printArguments(name, args, ret) {
        var body = "Method: " + name;
        for (var i = 0; i < args.length; i++) {
            try {
                body += "\n    Arguments[" + i + "]: ";
                body += args[i];
            } catch (e) {
                /* ignore */
            }
        }
        if (ret !== undefined) {
            body += "\n    Return: " + ret;
        }
        send({"helper_method": body});
    }

    /**
     * 打印当前参数和返回值
     */
    addMethod(this, "printArguments", function(args, ret) {
        printArguments(helper.getStackTrace()[0], args, ret);
    });

    /**
     * 打印当前参数和返回值
     * :param message:      回显的信息
     */
    addMethod(this, "printArguments", function(message, args, ret) {
        printArguments(message, args, ret);
    });
}