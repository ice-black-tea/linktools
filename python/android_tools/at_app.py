#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
@author  : Hu Ji
@file    : at_app.py 
@time    : 2019/01/02
@site    :  
@software: PyCharm 

              ,----------------,              ,---------,
         ,-----------------------,          ,"        ,"|
       ,"                      ,"|        ,"        ,"  |
      +-----------------------+  |      ,"        ,"    |
      |  .-----------------.  |  |     +---------+      |
      |  |                 |  |  |     | -==----'|      |
      |  | $ sudo rm -rf / |  |  |     |         |      |
      |  |                 |  |  |/----|`---=    |      |
      |  |                 |  |  |   ,/|==== ooo |      ;
      |  |                 |  |  |  // |(((( [33]|    ,"
      |  `-----------------'  |," .;'| |((((     |  ,"
      +-----------------------+  ;;  | |         |,"
         /_)______________(_/  //'   | +---------+
    ___________________________/___  `,
   /  oooooooooooooooo  .o.  oooo /,   \,"-----------
  / ==ooooooooooooooo==.o.  ooo= //   ,`\--{)B     ,"
 /_==__==========__==_ooo__ooo=_/'   /___________,"
"""
import argparse
import json

import colorama
from colorama import Fore, Style, Back

import android_tools
from android_tools import adb_device, utils


class write_sytle:

    def __init__(self, fore, back, style):
        self.fore = fore
        self.back = back
        self.style = style


class write_stream:
    STYLE_TITLE = write_sytle(None, None, Style.BRIGHT)
    STYLE_NORMAL = write_sytle(None, None, None)
    STYLE_USELESS = write_sytle(Fore.YELLOW, Back.WHITE, Style.BRIGHT)
    STYLE_IMPORTANT = write_sytle(Fore.RED, Back.WHITE, Style.BRIGHT)

    def __init__(self, file=None):
        colorama.init(True)
        self.file = file

    def print(self, text="", style: write_sytle = STYLE_NORMAL, indent: int = 0):
        if style.style is not None:
            text = style.style + text
        if style.back is not None:
            text = style.back + text
        if style.fore is not None:
            text = style.fore + text
        if indent > 0:
            text = " " * indent + text
        return print(text, file=self.file)


class permission_info:

    def __init__(self, obj: dict):
        self.name = utils.item(obj, "name", default="")
        self.protection = utils.item(obj, "protection", default="normal")

    def is_secure(self):
        return self.protection not in ["dangerous", "normal"]

    def is_defined(self):
        return not utils.empty(self.name)

    def dump(self, stream: write_stream, identity: str = "Permission", indent: int = 0, **kwargs):
        if self.is_defined():
            style = stream.STYLE_NORMAL
            if not self.is_secure():
                style = stream.STYLE_IMPORTANT
            stream.print("%s [%s] %s" % (identity, self.name, self.protection), style=style, indent=indent)


class component_info:

    def __init__(self, obj: dict):
        self.name = utils.item(obj, "name", default="")
        self.exported = utils.item(obj, "exported", default=False)
        self.enabled = utils.item(obj, "enabled", default=False)

    def dump(self, stream: write_stream, identity: str = "Component", indent: int = 0, **kwargs):
        raise Exception("not yet implmented")


class activity_info(component_info):

    def __init__(self, obj: dict):
        super().__init__(obj)
        self.permission = permission_info(utils.item(obj, "permission", default={}))

    def dump(self, stream: write_stream, identity: str = "Activity", indent: int = 0, **kwargs):
        style = stream.STYLE_NORMAL
        text = "%s [%s]" % (identity, self.name)
        if not self.enabled:
            style = stream.STYLE_USELESS
            text = text + " enable=false"
        elif self.exported:
            if not self.permission.is_secure():
                style = stream.STYLE_IMPORTANT
            text = text + " exported=true"
        stream.print(text, style=style, indent=indent)
        self.permission.dump(stream, indent=indent + 4)


class service_info(component_info):

    def __init__(self, obj: dict):
        super().__init__(obj)
        self.permission = permission_info(utils.item(obj, "permission", default={}))

    def dump(self, stream: write_stream, identity: str = "Service", indent: int = 0, **kwargs):
        style = stream.STYLE_NORMAL
        text = "%s [%s]" % (identity, self.name)
        if not self.enabled:
            style = stream.STYLE_USELESS
            text = text + " enable=false"
        elif self.exported:
            if not self.permission.is_secure():
                style = stream.STYLE_IMPORTANT
            text = text + " exported=true"
        stream.print(text, style=style, indent=indent)
        self.permission.dump(stream, indent=indent + 4)


class receiver_info(component_info):

    def __init__(self, obj: dict):
        super().__init__(obj)
        self.permission = permission_info(utils.item(obj, "permission", default={}))

    def dump(self, stream: write_stream, identity: str = "Receiver", indent: int = 0, **kwargs):
        style = stream.STYLE_NORMAL
        text = "%s [%s]" % (identity, self.name)
        if not self.enabled:
            style = stream.STYLE_USELESS
            text = text + " enable=false"
        elif self.exported:
            if not self.permission.is_secure():
                style = stream.STYLE_IMPORTANT
            text = text + " exported=true"
        stream.print(text, style=style, indent=indent)
        self.permission.dump(stream, indent=indent + 4)


class pattern_matcher:

    def __init__(self, obj: dict):
        self.path = utils.item(obj, "path", default="")
        self.type = utils.item(obj, "type", default="literal")

    def dump(self, stream: write_stream, identity: str = "PatternMatcher", indent: int = 0, **kwargs):
        style = stream.STYLE_NORMAL
        stream.print("%s [path=%s, type=%s]" % (identity, self.path, self.type), style=style, indent=indent)


class path_permission(pattern_matcher):

    def __init__(self, obj: dict):
        super().__init__(obj)
        self.readPermission = permission_info(utils.item(obj, "readPermission", default={}))
        self.writePermission = permission_info(utils.item(obj, "writePermission", default={}))

    def dump(self, stream: write_stream, identity: str = "PathPermission", indent: int = 0, **kwargs):
        style = stream.STYLE_NORMAL
        if not self.readPermission.is_secure() or not self.writePermission.is_secure():
            style = stream.STYLE_IMPORTANT
        stream.print("%s [path=%s, type=%s]" % (identity, self.path, self.type), style=style, indent=indent)
        self.readPermission.dump(stream, indent=indent + 4, identity="ReadPermission")
        self.writePermission.dump(stream, indent=indent + 4, identity="WritePermission")


class provider_info(component_info):

    def __init__(self, obj: dict):
        super().__init__(obj)
        self.authority = utils.item(obj, "authority", default="")
        self.readPermission = permission_info(utils.item(obj, "readPermission", default={}))
        self.writePermission = permission_info(utils.item(obj, "writePermission", default={}))
        self.uriPermissionPatterns = utils.item(obj, "uriPermissionPatterns", default=[])
        self.pathPermissions = utils.item(obj, "pathPermissions", default=[])

    def dump(self, stream: write_stream, identity: str = "Provider", indent: int = 0, **kwargs):
        style = stream.STYLE_NORMAL
        text = "%s [%s]" % (identity, self.name)
        if not self.enabled:
            style = stream.STYLE_USELESS
            text = text + " enable=false"
        elif self.exported:
            if not self.readPermission.is_secure() or not self.writePermission.is_secure():
                style = stream.STYLE_IMPORTANT
            text = text + " exported=true"
        stream.print(text, style=style, indent=indent)

        self.readPermission.dump(stream, indent=indent + 4, identity="ReadPermission")
        self.writePermission.dump(stream, indent=indent + 4, identity="WritePermission")

        if not utils.empty(self.uriPermissionPatterns):
            stream.print("uriPermissionPatterns:", indent=indent + 4)
            for uriPermissionPattern in self.uriPermissionPatterns:
                matcher = pattern_matcher(uriPermissionPattern)
                matcher.dump(stream, indent=indent + 8, identity="UriPermissionPattern")
                del matcher

        if not utils.empty(self.pathPermissions):
            stream.print("pathPermissions:", indent=indent + 4)
            for pathPermission in self.pathPermissions:
                permission = path_permission(pathPermission)
                permission.dump(stream, indent=indent + 8, identity="PathPermission")
                del permission


class package_info:

    def __init__(self, obj: dict):
        self.name = utils.item(obj, "name", default="")
        self.appName = utils.item(obj, "appName", default="")
        self.userId = utils.item(obj, "userId", default="")
        self.gids = utils.item(obj, "gids", default=[])
        self.sourceDir = utils.item(obj, "sourceDir", default="")
        self.versionCode = utils.item(obj, "versionCode", default="")
        self.versionName = utils.item(obj, "versionName", default="")
        self.enabled = utils.item(obj, "enabled", default="")
        self.system = utils.item(obj, "system", default="")
        self.debuggable = utils.item(obj, "debuggable", default="")
        self.allowBackup = utils.item(obj, "allowBackup", default="")

        self.permissions = utils.item(obj, "permissions", default=[])
        self.activities = utils.item(obj, "activities", default=[])
        self.services = utils.item(obj, "services", default=[])
        self.receivers = utils.item(obj, "receivers", default=[])
        self.providers = utils.item(obj, "providers", default=[])

    def dump(self, stream: write_stream, indent: int = 0, identity: str = "Package"):
        stream.print("%s [%s]" % (identity, self.name), style=stream.STYLE_TITLE, indent=indent)
        stream.print("name=%s" % self.appName, indent=indent + 4)
        stream.print("userId=%s" % self.userId, indent=indent + 4)
        stream.print("gids=%s" % self.gids, indent=indent + 4)
        stream.print("sourceDir=%s" % self.sourceDir, indent=indent + 4)
        stream.print("versionCode=%s" % self.versionCode, indent=indent + 4)
        stream.print("versionName=%s" % self.versionName, indent=indent + 4)
        stream.print("enabled=%s" % self.enabled, indent=indent + 4)
        stream.print("system=%s" % self.system, indent=indent + 4)
        stream.print("debuggable=%s" % self.debuggable,
                     style=stream.STYLE_IMPORTANT if self.debuggable else stream.STYLE_NORMAL,
                     indent=indent + 4)
        stream.print("allowBackup=%s" % self.allowBackup,
                     style=stream.STYLE_IMPORTANT if self.allowBackup else stream.STYLE_NORMAL,
                     indent=indent + 4)
        stream.print()

        if not utils.empty(self.permissions):
            stream.print("permissions:", indent=indent + 4)
            for permission in self.permissions:
                info = permission_info(permission)
                info.dump(stream, indent=indent + 8)
                del info
            stream.print()

        if not utils.empty(self.activities):
            stream.print("activitys:", indent=indent + 4)
            for activity in self.activities:
                info = activity_info(activity)
                info.dump(stream, indent=indent + 8)
                del info
            stream.print()

        if not utils.empty(self.services):
            stream.print("services:", indent=indent + 4)
            for service in self.services:
                info = service_info(service)
                info.dump(stream, indent=indent + 8)
                del info
            stream.print()

        if not utils.empty(self.receivers):
            stream.print("receivers:", indent=indent + 4)
            for receiver in self.receivers:
                info = receiver_info(receiver)
                info.dump(stream, indent=indent + 8)
                del info
            stream.print()

        if not utils.empty(self.providers):
            stream.print("providers:", indent=indent + 4)
            for provider in self.providers:
                info = provider_info(provider)
                info.dump(stream, indent=indent + 8)
                del info
            stream.print()

        stream.print()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='fetch application info')
    parser.add_argument('-v', '--version', action='version', version='%(prog)s ' + android_tools.__version__)
    parser.add_argument('-s', '--serial', action='store', default=None,
                        help='use device with given serial')

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-a', '--all', action='store_true', default=False,
                       help='fetch all apps')
    group.add_argument('-t', '--top', action='store_true', default=False,
                       help='fetch top-level app only')
    group.add_argument('-p', '--packages', metavar="pkg", action='store', nargs='+', default=None,
                       help='fetch target apps')

    parser.add_argument('-o', '--order-by', metavar="field", action='store', nargs='+', default=None,
                        choices=['name', 'appName', 'userId'], help='order by target field')

    args = parser.parse_args()

    device = adb_device(args.serial)

    dex_args = ["package"]
    if args.top is True:
        dex_args = ["package", "-p", device.top_package()]
    elif not utils.empty(args.packages):
        dex_args = ["package", "-p", *args.packages]
    packages = json.loads(device.call_dex(*dex_args, capture_output=True))
    if not utils.empty(args.order_by):
        packages = sorted(packages, key=lambda x: [utils.item(x, k, default="") for k in args.order_by])

    stream = write_stream()
    for package in packages:
        info = package_info(package)
        info.dump(stream)
        del info
