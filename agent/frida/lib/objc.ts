// https://github.com/frida/frida-objc-bridge/blob/main/index.js

/**
 *  用于方便调用frida的ObjC方法
 */
export class ObjCHelper {

    /**
     * 为method添加properties
     * @param method 方法对象
     */
    private $fixMethod(clazz: ObjC.Object, method: ObjC.ObjectMethod): void {
        const implementation = method["origImplementation"] || method.implementation;
        const className = clazz.toString();
        const methodName = ObjC.selectorAsString(method.selector);
        const isClassMethod = ObjC.classes.NSThread.hasOwnProperty(methodName);
        Object.defineProperties(method, {
            className: {
                configurable: true,
                enumerable: true,
                get() {
                    return className;
                },
            },
            methodName: {
                configurable: true,
                enumerable: true,
                get() {
                    return methodName;
                },
            },
            name: {
                configurable: true,
                enumerable: true,
                get() {
                    return (isClassMethod ? "+" : "-") + "[" + className + " " + methodName + "]";
                }
            },
            origImplementation: {
                configurable: true,
                enumerable: true,
                get() {
                    return implementation;
                }
            },
            toString: {
                value: function () {
                    return this.name;
                }
            }
        });
    }

    /**
     * hook指定方法对象
     * @param method 方法对象
     * @param impl hook实现，如调用原函数： function(obj, args) { return this(obj, sel, args); }
     */
    private $hookMethod(method: ObjC.ObjectMethod, impl: (obj: any, args: any[]) => any = null): void {
        if (impl != null) {
            method.implementation = ObjC.implement(method, function () {
                const self = this;
                const args = Array.prototype.slice.call(arguments);
                const obj = args.shift();
                const sel = args.shift();
                const proxy: ObjC.ObjectMethod = new Proxy(method, {
                    get: function (target, p: string | symbol, receiver: any) {
                        if (p in self) {
                            return self[p];
                        }
                        return target[p];
                    },
                    apply: function (target, thisArg: any, argArray: any[]) {
                        const obj = argArray[0];
                        const args = argArray[1];
                        return target["origImplementation"].apply(null, [].concat(obj, sel, args));
                    }
                });
                return impl.call(proxy, obj, args);
            });
            Log.i("Hook method: " + method);
        } else {
            method.implementation = method["origImplementation"];
            Log.i("Unhook method: " + pretty2String(method));
        }
    }

    /**
     * 获取hook实现，调用原方法并发送调用事件
     * @param options hook选项，如：{stack: true, args: true, thread: true}
     * @returns hook实现
     */
    hookMethod(
        clazz: string | ObjC.Object,
        method: string | ObjC.ObjectMethod,
        impl: (obj: ObjC.Object, args: any[]) => any = null
    ): void {
        var targetClass: any = clazz;
        if (typeof (targetClass) === "string") {
            targetClass = ObjC.classes[targetClass];
        }
        if (targetClass === void 0) {
            throw Error("cannot find class \"" + clazz + "\"");
        }
        var targetMethod: any = method;
        if (typeof (targetMethod) === "string") {
            targetMethod = targetClass[targetMethod];
        }
        if (targetMethod === void 0) {
            throw Error("cannot find method \"" + method + "\" in class \"" + targetClass + "\"");
        }
        this.$fixMethod(targetClass, targetMethod);
        this.$hookMethod(targetMethod, impl);
    }

    /**
     * 获取hook实现，调用原方法并发送调用事件
     * @param options hook选项，如：{stack: true, args: true, thread: true}
     * @returns hook实现
     */
    hookMethods(
        clazz: string | ObjC.Object,
        name: string,
        impl: (obj: ObjC.Object, args: any[]) => any = null
    ): void {
        var targetClass: any = clazz;
        if (typeof (targetClass) === "string") {
            targetClass = ObjC.classes[targetClass];
        }
        if (targetClass === void 0) {
            throw Error("cannot find class \"" + clazz + "\"");
        }
        const length = targetClass.$ownMethods.length;
        for (let i = 0; i < length; i++) {
            const method = targetClass.$ownMethods[i];
            if (method.indexOf(name) >= 0) {
                const targetMethod = targetClass[method];
                this.$fixMethod(targetClass, targetMethod);
                this.$hookMethod(targetMethod, impl);
            }
        }
    }

    /**
     * 获取hook实现，调用原方法并发送调用事件
     * @param options hook选项，如：{stack: true, args: true, thread: true}
     * @returns hook实现
     */
    getEventImpl(options: any): (obj: any, args: any[]) => any {
        const self = this;

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
                event["class_name"] = new ObjC.Object(obj).$className
                event["method_name"] = this.name;
                event["method_simple_name"] = this.methodName;
            }
            if (opts.thread !== false) {
                event["thread_id"] = Process.getCurrentThreadId();
                event["thread_name"] = ObjC.classes.NSThread.currentThread().name().toString()
            }
            if (opts.args !== false) {
                const objectArgs = []
                for (let i = 0; i < args.length; i++) {
                    objectArgs.push(self.convert2ObjcObject(args[i]));
                }
                event["args"] = pretty2Json(objectArgs);
                event["result"] = null;
                event["error"] = null;
            }
            try {
                const result = this(obj, args);
                if (opts.args !== false) {
                    event["result"] = pretty2Json(self.convert2ObjcObject(result));
                }
                return result;
            } catch (e) {
                if (opts.args !== false) {
                    event["error"] = pretty2Json(e);
                }
                throw e;
            } finally {
                if (opts.stack !== false) {
                    const stack = [];
                    const backtracer = opts.stack !== "fuzzy" ? Backtracer.ACCURATE : Backtracer.FUZZY;
                    const elements = Thread.backtrace(this.context, backtracer);
                    for (let i = 0; i < elements.length; i++) {
                        stack.push(getDebugSymbolFromAddress(elements[i]).toString());
                    }
                    event["stack"] = stack;
                }
                Emitter.emit(event);
            }
        };
    }

    convert2ObjcObject(obj: any) {
        if (obj instanceof NativePointer) {
            return new ObjC.Object(obj);
        } else if (typeof obj === 'object' && obj.hasOwnProperty('handle')) {
            return new ObjC.Object(obj);
        }
        return obj;
    }

}
