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
from android_tools import utils, adb_device
from android_tools import package, permission, component, activity, service, receiver, provider, intent_filter


class print_level:
    useless = 100
    normal = 200
    dangerous_normal = 250
    dangerous = 300
    title = 400
    min = useless
    max = title


class print_stream(print_level):

    def __init__(self, max_level=print_level.max, min_level=print_level.min, file=None):
        colorama.init(True)
        self.max = max_level
        self.min = min_level
        self.file = file

    def print(self, text: str = "", indent: int = 0, level=print_level.normal):
        if level < self.min or level > self.max:
            pass
        elif level == print_level.title:
            print(" " * indent + Style.BRIGHT + text, file=self.file)
        elif level == print_level.dangerous:
            print(" " * indent + Fore.RED + Back.WHITE + Style.BRIGHT + text, file=self.file)
        elif level == print_level.useless:
            print(" " * indent + Fore.YELLOW + Back.WHITE + Style.BRIGHT + text, file=self.file)
        else:
            print(" " * indent + text, file=self.file)

    def print_line(self):
        print("", file=self.file)


class print_stream_wrapper(print_level):

    def __init__(self, stream: print_stream, max_level: int = print_level.max, min_level: int = print_level.min):
        self.stream = stream
        self.max_level = max_level
        self.min_level = min_level

    def print(self, text: str ="", indent: int = 0, level=print_level.normal):
        if level > self.max_level:
            level = self.max_level
        elif level < self.min_level:
            level = self.min_level
        self.stream.print(text, indent=indent, level=level)

    def print_line(self):
        self.stream.print_line()

    def create(self, max_level: int = print_level.max, min_level: int = print_level.min):
        if max_level > self.max_level:
            max_level = self.max_level
        elif min_level < self.min_level:
            min_level = self.min_level
        return print_stream_wrapper(self.stream, max_level=max_level, min_level=min_level)


class package_printer:

    def __init__(self, stream: print_stream, package: package):
        self.package = package
        self.max_level = print_level.max if self.package.enabled else print_level.useless
        self.min_level = print_level.min
        self.stream = print_stream_wrapper(stream, max_level=self.max_level, min_level=self.min_level)

    def print_package(self, indent: int = 0):
        self.stream.print("Package [%s]" % self.package, indent=indent, level=self.stream.title)
        self.stream.print("name=%s" % self.package.appName, indent=indent + 4, level=self.stream.normal)
        self.stream.print("userId=%s" % self.package.userId, indent=indent + 4, level=self.stream.normal)
        self.stream.print("gids=%s" % self.package.gids, indent=indent + 4, level=self.stream.normal)
        self.stream.print("sourceDir=%s" % self.package.sourceDir, indent=indent + 4, level=self.stream.normal)
        self.stream.print("versionCode=%s" % self.package.versionCode, indent=indent + 4, level=self.stream.normal)
        self.stream.print("versionName=%s" % self.package.versionName, indent=indent + 4, level=self.stream.normal)
        self.stream.print("enabled=%s" % self.package.enabled, indent=indent + 4, level=self.stream.normal)
        self.stream.print("system=%s" % self.package.system, indent=indent + 4, level=self.stream.normal)
        self.stream.print("debuggable=%s" % self.package.debuggable, indent=indent + 4,
                          level=self.stream.dangerous if self.package.debuggable else self.stream.normal)
        self.stream.print("allowBackup=%s" % self.package.allowBackup, indent=indent + 4,
                          level=self.stream.dangerous if self.package.allowBackup else self.stream.normal)
        self.stream.print_line()

    def print_requested_permissions(self, indent: int = 4):
        if not utils.empty(self.package.requestedPermissions):
            stream = self.stream.create(max_level=print_level.normal)
            self.stream.print("RequestedPermissions:", indent=indent, level=self.stream.title)
            for permission in self.package.requestedPermissions:
                self._print_permission(stream, permission, indent=indent + 4, identity="RequestedPermission")
            self.stream.print_line()

    def print_permissions(self, indent: int = 4):
        if not utils.empty(self.package.permissions):
            self.stream.print("Permissions:", indent=indent, level=stream.title)
            for permission in self.package.permissions:
                self._print_permission(self.stream, permission, indent=indent + 4, identity="Permission")
            self.stream.print_line()

    def print_activities(self, indent: int = 4):
        if not utils.empty(self.package.activities):
            self.stream.print("Activities:", indent=indent, level=stream.title)
            for activity in self.package.activities:
                self._print_component(self.stream, activity, indent=indent + 4, identity="Activity")
            self.stream.print_line()

    def print_services(self, indent: int = 4):
        if not utils.empty(self.package.services):
            self.stream.print("Services:", indent=indent, level=stream.title)
            for service in self.package.services:
                self._print_component(self.stream, service, indent=indent + 4, identity="Service")
            self.stream.print_line()

    def print_receivers(self, indent: int = 4):
        if not utils.empty(self.package.receivers):
            self.stream.print("Receivers:", indent=indent, level=stream.title)
            for receiver in self.package.receivers:
                self._print_component(self.stream, receiver, indent=indent + 4, identity="Receiver")
            self.stream.print_line()

    def print_providers(self, indent: int = 4):
        if not utils.empty(self.package.providers):
            self.stream.print("Providers:", indent=indent, level=stream.title)
            for provider in self.package.providers:
                self._print_component(self.stream, provider, indent=indent + 4, identity="Provider")
            self.stream.print_line()

    @staticmethod
    def _print_permission(stream: print_stream_wrapper, permission: permission, indent: int = 0, identity: str = None):
        if permission.is_defined():
            stream.print("%s [%s] %s" % (identity, permission, permission.protection), indent=indent,
                         level=stream.dangerous if permission.is_dangerous() else stream.normal)

    @staticmethod
    def _print_component(stream: print_stream_wrapper, component: component, indent: int = 0, identity: str = None):
        if not component.enabled:
            description = "disabled"
            level = stream.useless
            stream = stream.create(max_level=stream.useless)
        elif component.is_dangerous():
            description = "exported"
            level = stream.dangerous if component.is_dangerous() else stream.normal
            stream = stream.create(min_level=stream.dangerous_normal)
        else:
            description = "exported" if component.exported else ""
            level = stream.normal
            stream = stream.create(max_level=stream.normal)
        stream.print("%s [%s] %s" % (identity, component, description), indent=indent, level=level)

        if isinstance(component, activity) or isinstance(component, service) or isinstance(component, receiver):
            package_printer._print_permission(stream, component.permission, indent=indent + 4, identity="Permission")
        elif isinstance(component, provider):
            stream.print("Authority [%s]" % component.authority, indent=indent + 4, level=level)
            package_printer._print_permission(stream, component.readPermission, indent=indent + 4, identity="ReadPermission")
            package_printer._print_permission(stream, component.writePermission, indent=indent + 4, identity="writePermission")
            for pattern in component.uriPermissionPatterns:
                stream.print("UriPermissionPattern [%s]" % pattern, indent=indent + 4, level=level)
            for permission in component.pathPermissions:
                stream.print("PathPermission [%s]" % permission, indent=indent + 4,
                             level=stream.dangerous if permission.is_dangerous() else stream.normal)
                package_printer._print_permission(stream, permission.readPermission, indent=indent + 8, identity="ReadPermission")
                package_printer._print_permission(stream, permission.writePermission, indent=indent + 8, identity="writePermission")

        if not utils.empty(component.intents):
            for intent in component.intents:
                package_printer._print_intent(stream, intent, indent=indent + 4, level=level)

    @staticmethod
    def _print_intent(stream: print_stream_wrapper, intent: intent_filter, indent: int = 0, level: int = print_level.normal):
        stream.print("IntentFilter:", indent=indent, level=level)
        for action in intent.actions:
            stream.print("Action [%s]" % action, indent=indent + 4, level=level)
        for category in intent.categories:
            stream.print("Category [%s]" % category, indent=indent + 4, level=level)
        for scheme in intent.dataSchemes:
            stream.print("Scheme [%s]" % scheme, indent=indent + 4, level=level)
        for scheme in intent.dataSchemeSpecificParts:
            stream.print("Scheme [%s]" % scheme, indent=indent + 4, level=level)
        for authority in intent.dataAuthorities:
            stream.print("Authority [%s]" % authority, indent=indent + 4, level=level)
        for path in intent.dataPaths:
            stream.print("Path [%s]" % path, indent=indent + 4, level=level)
        for type in intent.dataTypes:
            stream.print("Type [%s]" % type, indent=indent + 4, level=level)


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
                       help='fetch target apps only')
    group.add_argument('--system', action='store_true', default=False,
                       help='fetch system apps only')
    group.add_argument('--non-system', action='store_true', default=False,
                       help='fetch non-system apps only')

    parser.add_argument('-b', '--basic-info', action='store_true', default=False,
                        help='display basic info only')
    parser.add_argument('-d', '--dangerous', action='store_true', default=False,
                        help='display dangerous permissions and components only')
    parser.add_argument('-o', '--order-by', metavar="field", action='store', nargs='+', default=None,
                        choices=['name', 'appName', 'userId'], help='order by target field')

    args = parser.parse_args()

    device = adb_device(args.serial)

    dex_args = ["package"]
    if args.top is True:
        dex_args = ["package", "-p", device.top_package()]
    elif not utils.empty(args.packages):
        dex_args = ["package", "-p", *args.packages]
    objs = json.loads(device.call_dex(*dex_args, capture_output=True))
    if not utils.empty(args.order_by):
        objs = sorted(objs, key=lambda x: [utils.item(x, k, default="") for k in args.order_by])

    stream = print_stream(min_level=print_level.dangerous_normal if args.dangerous else print_level.min)

    for obj in objs:
        printer = package_printer(stream, package(obj))

        if args.system and not printer.package.system:
            continue
        if args.non_system and printer.package.system:
            continue

        printer.print_package()

        if args.basic_info:
            continue

        if not args.dangerous:
            printer.print_requested_permissions()
            printer.print_permissions()
            printer.print_activities()
            printer.print_services()
            printer.print_receivers()
            printer.print_providers()
            continue

        if printer.package.has_dangerous_permission():
            printer.print_permissions()
        if printer.package.has_dangerous_activity():
            printer.print_activities()
        if printer.package.has_dangerous_service():
            printer.print_services()
        if printer.package.has_dangerous_receiver():
            printer.print_receivers()
        if printer.package.has_dangerous_provider():
            printer.print_providers()
