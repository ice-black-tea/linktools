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
            const origImpl: any = method.implementation;
            method.implementation = ObjC.implement(method, function () {
                const self = this;
                const args = Array.prototype.slice.call(arguments);
                const obj = args.shift();
                const sel = args.shift();
                const origMethod: ObjC.ObjectMethod = new Proxy(method, {
                    get: function (target, p: string | symbol, receiver: any) {
                        if (p == "context")
                            return self.context;
                        return target[p];
                    },
                    apply: function (target, thisArg: any, argArray: any[]) {
                        const obj = argArray.shift();
                        const args = argArray.shift();
                        return origImpl.apply(null, [].concat(obj, sel, args));
                    }
                });
                return impl.call(origMethod, obj, args);
            });
            Log.i("Hook method: " + method);
        } else {
            method.implementation = null;
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
        this.$fixMethod(targetClass, targetMethod)
        this.$hookMethod(targetMethod, impl);
    }

    /**
     * 获取hook实现，调用原方法并发送调用事件
     * @param options hook选项，如：{stack: true, args: true, thread: true}
     * @returns hook实现
     */
    getEventImpl(options: any): (obj: any, args: any[]) => any {
        const objCHelperThis = this;

        let methodOption = true;
        let threadOption = false;
        let stackOption = false;
        let argsOption = false;
        const extras = {};

        for (const key in options) {
            if (key == "thread") {
                methodOption = options[key];
            } else if (key == "thread") {
                threadOption = options[key];
            } else if (key == "stack") {
                stackOption = options[key];
            } else if (key == "args") {
                argsOption = options[key];
            } else {
                extras[key] = options[key];
            }
        }

        return function (obj, args) {
            const result = this(obj, args);
            const event = {};
            for (const key in extras) {
                event[key] = extras[key];
            }
            if (methodOption == true) {
                event["class_name"] = new ObjC.Object(obj).$className
                event["method_name"] = this.name;
                event["method_simple_name"] = this.methodName;
            }
            if (threadOption === true) {
                const thread = ObjC.classes.NSThread.currentThread();
                event["thread_name"] = thread.name().toString()
            }
            if (argsOption === true) {
                const objectArgs = []
                for (let i = 0; i < args.length; i++) {
                    objectArgs.push(objCHelperThis.convert2ObjcObject(args[i]));
                }
                event["args"] = pretty2Json(objectArgs);
                event["result"] = pretty2Json(objCHelperThis.convert2ObjcObject(result));
            }
            if (stackOption === true) {
                const stack = [];
                const elements = Thread.backtrace(this.context, Backtracer.ACCURATE);
                for (let i = 0; i < elements.length; i++) {
                    stack.push(DebugSymbol.fromAddress(elements[i]));
                }
                event["stack"] = stack;
            }
            send({ event: event });
            return result;
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
