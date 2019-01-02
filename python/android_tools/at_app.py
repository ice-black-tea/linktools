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

STYLE_TITLE = {"fore": None, "back": None, "style": Style.BRIGHT}
STYLE_NORMAL = {"fore": None, "back": None, "style": None}
STYLE_USELESS = {"fore": Fore.YELLOW, "back": Back.WHITE, "style": Style.BRIGHT}
STYLE_IMPORTANT = {"fore": Fore.RED, "back": Back.WHITE, "style": Style.BRIGHT}


class write_stream:

    def __init__(self, file=None):
        colorama.init(True)
        self.file = file

    def print(self, text="", fore: Fore = None, back: Back = None, style: Style = None, indent: int = 0):
        if style is not None:
            text = style + text
        if back is not None:
            text = back + text
        if fore is not None:
            text = fore + text
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
            style = STYLE_NORMAL
            if not self.is_secure():
                style = STYLE_IMPORTANT
            stream.print("%s [%s] %s" % (identity, self.name, self.protection), **style, indent=indent)


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
        style = STYLE_NORMAL
        text = "%s [%s]" % (identity, self.name)
        if not self.enabled:
            style = STYLE_USELESS
            text = text + " enable=false"
        elif self.exported:
            if not self.permission.is_secure():
                style = STYLE_IMPORTANT
            text = text + " exported=true"
        stream.print(text, **style, indent=indent)
        self.permission.dump(stream, indent=indent+4)


class service_info(component_info):

    def __init__(self, obj: dict):
        super().__init__(obj)
        self.permission = permission_info(utils.item(obj, "permission", default={}))

    def dump(self, stream: write_stream, identity: str = "Service", indent: int = 0, **kwargs):
        style = STYLE_NORMAL
        text = "%s [%s]" % (identity, self.name)
        if not self.enabled:
            style = STYLE_USELESS
            text = text + " enable=false"
        elif self.exported:
            if not self.permission.is_secure():
                style = STYLE_IMPORTANT
            text = text + " exported=true"
        stream.print(text, **style, indent=indent)
        self.permission.dump(stream, indent=indent+4)


class receiver_info(component_info):

    def __init__(self, obj: dict):
        super().__init__(obj)
        self.permission = permission_info(utils.item(obj, "permission", default={}))

    def dump(self, stream: write_stream, identity: str = "Receiver", indent: int = 0, **kwargs):
        style = STYLE_NORMAL
        text = "%s [%s]" % (identity, self.name)
        if not self.enabled:
            style = STYLE_USELESS
            text = text + " enable=false"
        elif self.exported:
            if not self.permission.is_secure():
                style = STYLE_IMPORTANT
            text = text + " exported=true"
        stream.print(text, **style, indent=indent)
        self.permission.dump(stream, indent=indent+4)


class pattern_matcher:

    def __init__(self, obj: dict):
        self.path = utils.item(obj, "path", default="")
        self.type = utils.item(obj, "type", default="literal")

    def dump(self, stream: write_stream, identity: str = "PatternMatcher", indent: int = 0, **kwargs):
        style = STYLE_NORMAL
        stream.print("%s [path=%s, type=%s]" % (identity, self.path, self.type), **style, indent=indent)


class path_permission(pattern_matcher):

    def __init__(self, obj: dict):
        super().__init__(obj)
        self.readPermission = permission_info(utils.item(obj, "readPermission", default={}))
        self.writePermission = permission_info(utils.item(obj, "writePermission", default={}))

    def dump(self, stream: write_stream, identity: str = "PathPermission", indent: int = 0, **kwargs):
        style = STYLE_NORMAL
        if not self.readPermission.is_secure() or not self.writePermission.is_secure():
            style = STYLE_IMPORTANT
        stream.print("%s [path=%s, type=%s]" % (identity, self.path, self.type), **style, indent=indent)
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
        style = STYLE_NORMAL
        text = "%s [%s]" % (identity, self.name)
        if not self.enabled:
            style = STYLE_USELESS
            text = text + " enable=false"
        elif self.exported:
            if not self.readPermission.is_secure() or not self.writePermission.is_secure():
                style = STYLE_IMPORTANT
            text = text + " exported=true"
        stream.print(text, **style, indent=indent)

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
        stream.print("%s [%s]" % (identity, self.name), style=Style.BRIGHT, indent=indent)
        stream.print("name=%s" % self.appName, indent=indent + 4)
        stream.print("userId=%s" % self.userId, indent=indent + 4)
        stream.print("gids=%s" % self.gids, indent=indent + 4)
        stream.print("sourceDir=%s" % self.sourceDir, indent=indent + 4)
        stream.print("versionCode=%s" % self.versionCode, indent=indent + 4)
        stream.print("versionName=%s" % self.versionName, indent=indent + 4)
        stream.print("enabled=%s" % self.enabled, indent=indent + 4)
        stream.print("system=%s" % self.system, indent=indent + 4)
        stream.print("debuggable=%s" % self.debuggable, **STYLE_IMPORTANT if self.debuggable else STYLE_NORMAL,
                     indent=indent + 4)
        stream.print("allowBackup=%s" % self.allowBackup, **STYLE_IMPORTANT if self.allowBackup else STYLE_NORMAL,
                     indent=indent + 4)
        stream.print()

        if not utils.empty(self.permissions):
            stream.print("permissions:", indent=indent + 4)
            for permission in self.activities:
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

    parser.add_argument('-p', '--packages', metavar="package", action='store', nargs='*', default=None,
                        help='target packages [default all packages]')

    args = parser.parse_args()

    device = adb_device(args.serial)

    args = ["package"] if utils.empty(args.packages) else ["package", "-p", *args.packages]
    packages = json.loads(device.call_dex(*args, capture_output=True))

    stream = write_stream()
    for package in packages:
        info = package_info(package)
        info.dump(stream)
