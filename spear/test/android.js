Java.perform(function () {
  
    // [*] Hook method: java.lang.Integer Integer.valueOf(int)
    // JavaHelper.hookMethod("java.lang.Integer", "valueOf", ["int"], function(obj, args) {
    //     return this.apply(obj, args);
    // });
  
    // [*] Hook method: java.lang.Integer Integer.valueOf(int)
    // [*] Hook method: java.lang.Integer Integer.valueOf(java.lang.String)
    // [*] Hook method: java.lang.Integer Integer.valueOf(java.lang.String, int)
    // JavaHelper.hookMethods("java.lang.Integer", "valueOf", function(obj, args) {
    //     return this.apply(obj, args);
    // });
  
    // [*] Hook method: int Integer.undefined()
    // [*] Hook method: void Integer.Integer(int)
    // [*] Hook method: void Integer.Integer(java.lang.String)
    // [*] Hook method: int Integer.bitCount(int)
    // [*] ...
    // [*] Hook method: long Integer.longValue()
    // [*] Hook method: short Integer.shortValue()
    // JavaHelper.hookClass("java.lang.Integer", function(obj, args) {
    //     return this.apply(obj, args);
    // });
  
    // hook HashMap.put, print stack and args
    JavaHelper.hookMethods("java.util.HashMap", "put", JavaHelper.getHookImpl({printStack: true, printArgs: true}));
  
    // hook HashMap.put, print stack and args
    // var HashMap = Java.use("java.util.HashMap");
    // HashMap.put.implementation = function() {
    //     var ret = JavaHelper.callMethod(this, arguments);
    //     JavaHelper.printStack();
    //     JavaHelper.printArguments(arguments, ret);
    //     return ret;
    // }

});
