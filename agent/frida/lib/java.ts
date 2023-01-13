/**
 *  https://github.com/frida/frida-java-bridge/blob/main/lib/class-factory.js
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


/**
 *  用于方便调用frida的java方法
 */
export class JavaHelper {

    excludeHookPackages: string[] = [
        "java.",
        "javax.",
        "android.",
        "androidx.",
    ]

    get objectClass(): Java.Wrapper {
        return Java.use("java.lang.Object");
    }

    get classClass(): Java.Wrapper {
        return Java.use("java.lang.Class");
    }

    get stringClass(): Java.Wrapper {
        return Java.use("java.lang.String");
    }

    get threadClass(): Java.Wrapper {
        return Java.use("java.lang.Thread");
    }

    get throwableClass(): Java.Wrapper {
        return Java.use("java.lang.Throwable");
    }

    get uriClass(): Java.Wrapper {
        return Java.use("android.net.Uri");
    }

    get urlClass(): Java.Wrapper {
        return Java.use("java.net.URL");
    }

    get mapClass(): Java.Wrapper {
        return Java.use("java.util.Map");
    }

    get applicationContext(): Java.Wrapper {
        const activityThreadClass = Java.use('android.app.ActivityThread');
        return activityThreadClass.currentApplication().getApplicationContext();
    }

    /**
     * 获取java类的类对象
     * @param className java类名
     * @param classloader java类所在的ClassLoader
     * @returns 类对象
     */
    findClass<T extends Java.Members<T> = {}>(className: string, classloader: Java.Wrapper = void 0): Java.Wrapper<T> {
        if (classloader !== void 0 && classloader != null) {
            var originClassloader = Java.classFactory.loader;
            try {
                Reflect.set(Java.classFactory, "loader", classloader);
                return Java.use(className);
            } finally {
                Reflect.set(Java.classFactory, "loader", originClassloader);
            }
        } else {
            if (parseInt(Java.androidVersion) < 7) {
                return Java.use(className);
            }
            var error = null;
            var loaders = Java.enumerateClassLoadersSync();
            for (var i in loaders) {
                try {
                    var clazz = this.findClass<T>(className, loaders[i]);
                    if (clazz != null) {
                        return clazz;
                    }
                } catch (e) {
                    if (error == null) {
                        error = e;
                    }
                }
            }
            throw error;
        }
    }

    /**
     * 获取类名
     * @param clazz 类对象
     * @returns 
     */
    private $getClassName<T extends Java.Members<T> = {}>(clazz: Java.Wrapper<T>): string {
        var className = clazz.$className;
        if (className != void 0) {
            return className;
        }
        className = clazz.__name__;
        if (className != void 0) {
            return className;
        }
        if (clazz.$classWrapper != void 0) {
            className = clazz.$classWrapper.$className;
            if (className != void 0) {
                return className;
            }
            className = clazz.$classWrapper.__name__;
            if (className != void 0) {
                return className;
            }
        }
        Log.e("Cannot get class name: " + clazz);
    }

    /**
     * 获取真实方法对象
     * @param clazz 类对象
     * @param methodName 方法名
     * @returns 方法对象
     */
    private $getClassMethod<T extends Java.Members<T> = {}>(clazz: Java.Wrapper<T>, methodName: string): Java.MethodDispatcher<T> {
        var method = clazz[methodName];
        if (method !== void 0) {
            return method;
        }
        if (methodName[0] == "$") {
            method = clazz["_" + methodName];
            if (method !== void 0) {
                return method;
            }
        }
        return void 0;
    }

    /**
     * 为method添加properties
     * @param method 方法对象
     */
    private $defineMethodProperties<T extends Java.Members<T> = {}>(method: Java.Method<T>): void {
        Object.defineProperties(method, {
            className: {
                configurable: true,
                enumerable: true,
                writable: false,
                value: this.$getClassName(method.holder)
            },
            name: {
                configurable: true,
                enumerable: true,
                get() {
                    const ret = this.returnType.className;
                    const name = this.className + "." + this.methodName;
                    let args = "";
                    if (this.argumentTypes.length > 0) {
                        args = this.argumentTypes[0].className;
                        for (let i = 1; i < this.argumentTypes.length; i++) {
                            args = args + ", " + this.argumentTypes[i].className;
                        }
                    }
                    return ret + " " + name + "(" + args + ")";
                }
            },
            toString: {
                configurable: true,
                value: function () {
                    return this.name;
                }
            }
        });
    }

    /**
     * hook指定方法对象
     * @param method 方法对象
     * @param impl hook实现，如调用原函数： function(obj, args) { return this(obj, args); }
     */
    private $hookMethod<T extends Java.Members<T> = {}>(
        method: Java.Method<T>,
        impl: (obj: Java.Wrapper<T>, args: any[]) => any = null
    ): void {
        if (impl != null) {
            const proxy = new Proxy(method, {
                apply: function (target, thisArg: any, argArray: any[]) {
                    const obj = argArray[0];
                    const args = argArray[1];
                    return target.apply(obj, args);
                }
            });
            method.implementation = function () {
                return impl.call(proxy, this, Array.prototype.slice.call(arguments));
            };
            Log.i("Hook method: " + method);
        } else {
            method.implementation = null;
            Log.i("Unhook method: " + method);
        }
    }

    /**
     * hook指定方法对象
     * @param clazz java类名/类对象
     * @param method java方法名/方法对象
     * @param signatures java方法签名，为null表示不设置签名
     * @param impl hook实现，如调用原函数： function(obj, args) { return this(obj, args); }
     */
    hookMethod<T extends Java.Members<T> = {}>(
        clazz: string | Java.Wrapper<T>,
        method: string | Java.Method<T>,
        signatures: (string | Java.Wrapper<T>)[],
        impl: (obj: Java.Wrapper<T>, args: any[]) => any = null
    ): void {
        var targetMethod: any = method;
        if (typeof (targetMethod) === "string") {
            var methodName = targetMethod;
            var targetClass: any = clazz;
            if (typeof (targetClass) === "string") {
                targetClass = this.findClass(targetClass);
            }
            const method = this.$getClassMethod(targetClass, methodName);
            if (method === void 0 || method.overloads === void 0) {
                Log.w("Cannot find method: " + this.$getClassName(targetClass) + "." + methodName);
                return;
            }
            if (signatures != null) {
                var targetSignatures: any[] = signatures;
                for (var i in targetSignatures) {
                    if (typeof (targetSignatures[i]) !== "string") {
                        targetSignatures[i] = this.$getClassName(targetSignatures[i]);
                    }
                }
                targetMethod = method.overload.apply(method, targetSignatures);
            } else if (method.overloads.length == 1) {
                targetMethod = method.overloads[0];
            } else {
                throw Error(this.$getClassName(targetClass) + "." + methodName + " has too many overloads");
            }
        }
        this.$defineMethodProperties(targetMethod);
        this.$hookMethod(targetMethod, impl);
    }

    /**
     * hook指定方法名的所有重载
     * @param clazz java类名/类对象
     * @param method java方法名
     * @param impl hook实现，如调用原函数： function(obj, args) { return this(obj, args); }
     */
    hookMethods<T extends Java.Members<T> = {}>(
        clazz: string | Java.Wrapper<T>,
        methodName: string,
        impl: (obj: Java.Wrapper<T>, args: any[]) => any = null
    ): void {
        var targetClass: any = clazz;
        if (typeof (targetClass) === "string") {
            targetClass = this.findClass(targetClass);
        }
        var method = this.$getClassMethod(targetClass, methodName);
        if (method === void 0 || method.overloads === void 0) {
            Log.w("Cannot find method: " + this.$getClassName(targetClass) + "." + methodName);
            return;
        }
        for (var i = 0; i < method.overloads.length; i++) {
            const targetMethod = method.overloads[i];
            /* 过滤一些不存在的方法（拿不到返回值） */
            if (targetMethod.returnType !== void 0 &&
                targetMethod.returnType.className !== void 0) {
                this.$defineMethodProperties(targetMethod);
                this.$hookMethod(targetMethod, impl);
            }
        }
    }

    /**
     * hook指定类的所有构造方法
     * @param clazz java类名/类对象
     * @param impl hook实现，如调用原函数： function(obj, args) { return this(obj, args); }
     */
    hookAllConstructors<T extends Java.Members<T> = {}>(
        clazz: string | Java.Wrapper<T>,
        impl: (obj: Java.Wrapper<T>, args: any[]) => any = null
    ): void {
        var targetClass: any = clazz;
        if (typeof (targetClass) === "string") {
            targetClass = this.findClass(targetClass);
        }
        this.hookMethods(targetClass, "$init", impl);
    }

    $isExcludeClass(className: string) {
        for (const i in this.excludeHookPackages) {
            if (className.indexOf(this.excludeHookPackages[i]) == 0) {
                return true;
            }
        }
        return false;
    }

    /**
     * hook指定类的所有成员方法
     * @param clazz java类名/类对象
     * @param impl hook实现，如调用原函数： function(obj, args) { return this(obj, args); }
     */
    hookAllMethods<T extends Java.Members<T> = {}>(
        clazz: string | Java.Wrapper<T>,
        impl: (obj: Java.Wrapper<T>, args: any[]) => any = null
    ): void {
        var targetClass: any = clazz;
        if (typeof (targetClass) === "string") {
            targetClass = this.findClass(targetClass);
        }
        var methodNames = [];
        var superJavaClass = null;
        var targetJavaClass = targetClass.class;
        while (targetJavaClass != null) {
            var methods = targetJavaClass.getDeclaredMethods();
            for (let i = 0; i < methods.length; i++) {
                const method = methods[i];
                var methodName = method.getName();
                if (methodNames.indexOf(methodName) < 0) {
                    methodNames.push(methodName);
                    this.hookMethods(targetClass, methodName, impl);
                }
            }
            superJavaClass = targetJavaClass.getSuperclass();
            targetJavaClass.$dispose();
            if (superJavaClass == null) {
                // 不知道为啥，com.android.org.bouncycastle.crypto.paddings.BlockCipherPadding这个类获取superclass的时候会返回null
                break;
            }
            targetJavaClass = Java.cast(superJavaClass, this.classClass);
            if (this.$isExcludeClass(targetJavaClass.getName())) {
                break;
            }
        }
    }

    /**
     * hook指定类的所有方法（构造、成员方法）
     * @param clazz java类名/类对象
     * @param impl hook实现，如调用原函数： function(obj, args) { return this(obj, args); }
     */
    hookClass<T extends Java.Members<T> = {}>(
        clazz: string | Java.Wrapper<T>,
        impl: (obj: Java.Wrapper<T>, args: any[]) => any = null
    ): void {
        var targetClass: any = clazz;
        if (typeof (targetClass) === "string") {
            targetClass = this.findClass(targetClass);
        }
        this.hookAllConstructors(targetClass, impl);
        this.hookAllMethods(targetClass, impl);
    }

    /**
     * 获取hook实现，调用原方法并发送调用事件
     * @param options hook选项，如：{stack: true, args: true, thread: true}
     * @returns hook实现
     */
    getEventImpl<T extends Java.Members<T> = {}>(options: any): (obj: Java.Wrapper<T>, args: any[]) => any {
        const javaHelperThis = this;

        const opts = new function () {
            this.method = true;
            this.thread = false;
            this.stack = false;
            this.args = false;
            this.extras = {};
            for (const key in options) {
                if (key in this) {
                    this[key] = options[key];
                } else {
                    this.extras[key] = options[key];
                }
            }
        };

        return function (obj, args) {
            const event = {};
            for (const key in opts.extras) {
                event[key] = opts.extras[key];
            }
            if (opts.method !== false) {
                event["class_name"] = obj.$className;
                event["method_name"] = this.name;
                event["method_simple_name"] = this.methodName;
            }
            if (opts.thread !== false) {
                event["thread_id"] = Process.getCurrentThreadId();
                event["thread_name"] = javaHelperThis.threadClass.currentThread().getName();
            }
            if (opts.args !== false) {
                event["args"] = pretty2Json(args);
                event["result"] = null;
                event["error"] = null;
            }

            try {
                const result = this(obj, args);
                if (opts.args !== false) {
                    event["result"] = pretty2Json(result);
                }
                return result;
            } catch (e) {
                if (opts.args !== false) {
                    event["error"] = pretty2Json(e);
                }
                throw e;
            } finally {
                if (opts.stack !== false) {
                    event["stack"] = pretty2Json(javaHelperThis.getStackTrace());
                }
                Emitter.emit(event);
            }
        };
    }

    /**
     * 判断对象是不是java对象
     * @param obj js对象
     * @returns obj为java对象，则返回为true，否则为false
     */
    isJavaObject(obj: any): boolean {
        if (obj instanceof Object) {
            if (obj.hasOwnProperty("class") && obj.class instanceof Object) {
                const javaClass = obj.class;
                if (javaClass.hasOwnProperty("getName") &&
                    javaClass.hasOwnProperty("getDeclaredClasses") &&
                    javaClass.hasOwnProperty("getDeclaredFields") &&
                    javaClass.hasOwnProperty("getDeclaredMethods")) {
                    return true;
                }
            }
        }
        return false;
    }

    /**
     * 判断对象是否为java数组
     * @param obj js对象
     * @returns obj为java数组，则返回为true，否则为false
     */
    isJavaArray(obj: any): boolean {
        if (obj instanceof Object) {
            if (obj.hasOwnProperty("class") && obj.class instanceof Object) {
                const javaClass = obj.class;
                if (javaClass.hasOwnProperty("isArray") && javaClass.isArray()) {
                    return true;
                }
            }
        }
        return false;
    }

    /**
     * java数组转为js数组
     * @param clazz java类名/类对象
     * @param array java数组
     * @returns js数组
     */
    fromJavaArray<T extends Java.Members<T> = {}>(
        clazz: string | Java.Wrapper<T>,
        array: Java.Wrapper<T>
    ): Java.Wrapper<T>[] {
        var targetClass: any = clazz;
        if (typeof (targetClass) === "string") {
            targetClass = this.findClass(targetClass);
        }
        var result = [];
        var env = Java.vm.getEnv();
        for (var i = 0; i < env.getArrayLength(array.$handle); i++) {
            result.push(Java.cast(env.getObjectArrayElement(array.$handle, i), targetClass))
        }
        return result;
    }

    /**
     * 获取枚举值
     * @param clazz java类名/类对象
     * @param name java枚举名称
     * @returns java枚举值
     */
    getJavaEnumValue<T extends Java.Members<T> = {}>(
        clazz: string | Java.Wrapper<T>,
        name: string
    ): Java.Wrapper<T> {
        var targetClass: any = clazz;
        if (typeof (targetClass) === "string") {
            targetClass = this.findClass(targetClass);
        }
        var values = targetClass.class.getEnumConstants();
        if (!(values instanceof Array)) {
            values = this.fromJavaArray(targetClass, values);
        }
        for (var i = 0; i < values.length; i++) {
            if (values[i].toString() === name) {
                return values[i];
            }
        }
        throw new Error("Name of " + name + " does not match " + targetClass);
    }

    /**
     * 获取当前java栈
     * @param printStack 是否展示栈，默认为true
     * @param printArgs 是否展示参数，默认为true
     * @returns java栈对象
     */
    getStackTrace<T extends Java.Members<T> = {}>(): Java.Wrapper<T>[] {
        const result = [];
        const elements = this.throwableClass.$new().getStackTrace();
        for (let i = 0; i < elements.length; i++) {
            result.push(elements[i]);
        }
        return result;
    }

}