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
from colorama import Fore, Style

import android_tools
from android_tools import adb_device, utils


FORE_NORMAL = None
FORE_USELESS = Fore.MAGENTA
FORE_IMPORTANT = Fore.YELLOW


class permission_info:

    def __init__(self, obj: dict):
        self.name = utils.item(obj, "name", default="")
        self.protection = utils.item(obj, "protection", default="normal")

    def is_secure(self):
        return self.protection not in ["dangerous", "normal"]

    def is_defined(self):
        return not utils.empty(self.name)

    def __str__(self):
        return "%s %s" % (self.name, self.protection)


class component_info:

    def __init__(self, obj: dict):
        self.name = utils.item(obj, "name", default="")
        self.exported = utils.item(obj, "exported", default=False)
        self.enabled = utils.item(obj, "enabled", default=False)

    def __str__(self):
        return "%s %s %s" % (self.name, self.exported, self.enabled)


class activity_info(component_info):

    def __init__(self, obj: dict):
        super().__init__(obj)
        self.permission = permission_info(utils.item(obj, "permission", default={}))

    def __str__(self):
        return "%s %s %s" % (self.name, self.exported, self.enabled)


class service_info(component_info):

    def __init__(self, obj: dict):
        super().__init__(obj)
        self.permission = permission_info(utils.item(obj, "permission", default={}))

    def __str__(self):
        return "%s %s %s" % (self.name, self.exported, self.enabled)


class receiver_info(component_info):

    def __init__(self, obj: dict):
        super().__init__(obj)
        self.permission = permission_info(utils.item(obj, "permission", default={}))

    def __str__(self):
        return "%s %s %s" % (self.name, self.exported, self.enabled)


class pattern_matcher:

    def __init__(self, obj: dict):
        self.path = utils.item(obj, "path", default="")
        self.type = utils.item(obj, "type", default="literal")

    def __str__(self):
        return "%s %s" % (self.path, self.type)


class path_permission(pattern_matcher):

    def __init__(self, obj: dict):
        super().__init__(obj)
        self.path = permission_info(utils.item(obj, "readPermission", default={}))
        self.type = permission_info(utils.item(obj, "readPermission", default={}))

    def __str__(self):
        return "%s %s" % (self.path, self.type)


class provider_info(component_info):

    def __init__(self, obj: dict):
        super().__init__(obj)
        self.authority = utils.item(obj, "authority", default="")
        self.readPermission = permission_info(utils.item(obj, "readPermission", default={}))
        self.readPermission = permission_info(utils.item(obj, "readPermission", default={}))
        self.readPermission = permission_info(utils.item(obj, "readPermission", default={}))
        self.readPermission = permission_info(utils.item(obj, "readPermission", default={}))

    def __str__(self):
        return "%s %s %s" % (self.name, self.exported, self.enabled)


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

    def __str__(self):
        return "%s %s %s" % (self.name, self.exported, self.enabled)


def printex(text="", fore=None, back=None, style=None, **kwargs):
    if fore is not None:
        text = fore + text
    if back is not None:
        text = back + text
    if style is not None:
        text = style + text
    return print(text, **kwargs)


def dump_activities(pkg: str, activities: tuple):
    if utils.empty(activities):
        return

    printex("    activitys:")
    for activity in activities:
        info = activity_info(activity)

        text = "        Activity [%s/%s]" % (pkg, info.name)
        if not info.enabled:
            fore = FORE_USELESS
            text = text + "  disable"
        elif info.exported:
            fore = FORE_IMPORTANT if not info.permission.is_secure() else FORE_NORMAL
            text = text + "  exported"
        else:
            fore = FORE_NORMAL
        if info.permission.is_defined():
            text = text + "\r\n" \
                   "            permission=%s  %s" % (info.permission.name, info.permission.protection)
        printex(text, fore=fore)


def dump_services(pkg: str, services: tuple):
    if utils.empty(services):
        return

    printex("    services:")
    for service in services:
        info = service_info(service)

        text = "        Service [%s/%s]" % (pkg, info.name)
        if not info.enabled:
            fore = FORE_USELESS
            text = text + "  disable"
        elif info.exported:
            fore = FORE_IMPORTANT if not info.permission.is_secure() else FORE_NORMAL
            text = text + "  exported"
        else:
            fore = FORE_NORMAL
        if info.permission.is_defined():
            text = text + "\r\n" \
                   "            permission=%s  %s" % (info.permission.name, info.permission.protection)
        printex(text, fore=fore)


def dump_receivers(pkg: str, receivers: tuple):
    if utils.empty(receivers):
        return

    printex("    receivers:")
    for receiver in receivers:
        info = receiver_info(receiver)

        text = "        Receiver [%s/%s]" % (pkg, info.name)
        if not info.enabled:
            fore = FORE_USELESS
            text = text + "  disable"
        elif info.exported:
            fore = FORE_IMPORTANT if not info.permission.is_secure() else FORE_NORMAL
            text = text + "  exported"
        else:
            fore = FORE_NORMAL
        if info.permission.is_defined():
            text = text + "\r\n" \
                   "            permission=%s  %s" % (info.permission.name, info.permission.protection)
        printex(text, fore=fore)


def dump_providers(pkg: str, providers: tuple):
    if utils.empty(providers):
        return

    printex("    providers:")
    for provider in providers:
        info = provider_info(provider)

        text = "        Provider [%s/%s]" % (pkg, info.name)
        if not info.enabled:
            fore = FORE_USELESS
            text = text + "  disable"
        elif info.exported:
            fore = FORE_IMPORTANT if info.authority in ["dangerous", "normal"] else FORE_NORMAL
            text = text + "  exported"
        else:
            fore = FORE_NORMAL
        if not utils.empty(info.authority):
            text = text + "\r\n            authority=%s  " % info.authority
        printex(text, fore=fore)


def dump_package(package: dict):
    info = package_info(package)
    printex("Package [%s]" % info.name, style=Style.BRIGHT)
    printex("    name=%s" % info.appName)
    printex("    userId=%s" % info.userId)
    printex("    gids=%s" % info.gids)
    printex("    sourceDir=%s" % info.sourceDir)
    printex("    versionCode=%s" % info.versionCode)
    printex("    versionName=%s" % info.versionName)
    printex("    enabled=%s" % info.enabled)
    printex("    system=%s" % info.system)
    printex("    debuggable=%s" % info.debuggable, fore=FORE_IMPORTANT if info.debuggable else None)
    printex("    allowBackup=%s" % info.allowBackup, fore=FORE_IMPORTANT if info.allowBackup else None)

    printex()
    dump_activities(info.name, info.activities)
    printex()
    dump_services(info.name, info.services)
    printex()
    dump_receivers(info.name, info.receivers)
    printex()
    dump_providers(info.name, info.providers)
    printex()


if __name__ == '__main__':
    colorama.init(True)

    parser = argparse.ArgumentParser(description='get app info')
    parser.add_argument('-v', '--version', action='version', version='%(prog)s ' + android_tools.__version__)
    parser.add_argument('-s', '--serial', action='store', default=None,
                        help='use device with given serial')

    args = parser.parse_args()

    device = adb_device(args.serial)
    packages = json.loads(device.call_dex("package", "-p", device.top_package(), capture_output=True))

    for package in packages:
        dump_package(package)

