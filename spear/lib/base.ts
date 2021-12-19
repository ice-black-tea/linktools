export class Base {

    /**
     * 为自身添加方法，以参数个数重载
     * @param name 方法名
     * @param fn 方法实现
     */
    addMethod(name: string, fn: (...arys: any[]) => any) {
        this[name + '_$_$_' + fn.length] = fn;
        this[name] = function () {
            var prop = name + '_$_$_' + arguments.length;
            if (this.hasOwnProperty(prop)) {
                return this[prop].apply(this, arguments);
            } else {
                throw new Error("Argument count of " + arguments.length + " does not match " + name);
            }
        }
    }

    /**
     * 调用方法，忽略异常
     * @param fn 方法实现
     * @param defValue 出现异常时返回值
     * @returns 未出异常返回fn返回值，否则返回默认值
     */
    ignoreError(fn: (...arys: any[]) => any, defValue: any = undefined) {
        try {
            // ... ...
            return fn();
        } catch (e) {
            return defValue;
        }
    }

}
