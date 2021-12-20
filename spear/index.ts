import { Log } from "./lib/base";
import { JavaHelper } from "./lib/java";
import { ObjCHelper } from "./lib/objc";
import { AndroidHelper } from "./lib/android";

globalThis.Log = Log;
globalThis.JavaHelper = new JavaHelper();
globalThis.ObjCHelper = new ObjCHelper();
globalThis.AndroidHelper = new AndroidHelper()
