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
from argparse import ArgumentParser, Namespace
from typing import Optional

from linktools import utils, environ
from linktools.android import Package, Permission, \
    Component, Activity, Service, Receiver, Provider, IntentFilter
from linktools.cli import AndroidCommand


class PrintLevel:
    min = 0
    useless = 100
    normal = 200
    dangerous_normal = 250
    dangerous = 300
    title = 400
    max = 1000


class PrintStream(PrintLevel):

    def __init__(self, max_level=PrintLevel.max, min_level=PrintLevel.min, file=None):
        self.max = max_level
        self.min = min_level
        self.file = file

    def print(self, text: str = "", indent: int = 0, level=PrintLevel.normal):
        if not self.min <= level <= self.max:
            pass
        elif level == PrintLevel.title:
            environ.logger.info(text, style="bold", indent=indent)
        elif level == PrintLevel.dangerous:
            environ.logger.info(text, style="red bold", indent=indent)
        elif level == PrintLevel.useless:
            environ.logger.info(text, style="strike", indent=indent)
        else:
            environ.logger.info(text, indent=indent)

    def print_line(self):
        environ.logger.info("")


class PrintStreamWrapper(PrintLevel):

    def __init__(self, stream: PrintStream, max_level: int = PrintLevel.max, min_level: int = PrintLevel.min):
        self.stream = stream
        self.max_level = max_level
        self.min_level = min_level

    def print(self, text: str = "", indent: int = 0, level=PrintLevel.normal):
        if level > self.max_level:
            level = self.max_level
        elif level < self.min_level:
            level = self.min_level
        self.stream.print(text, indent=indent, level=level)

    def print_line(self):
        self.stream.print_line()

    def create(self, max_level: int = PrintLevel.max, min_level: int = PrintLevel.min):
        if max_level > self.max_level:
            max_level = self.max_level
        elif min_level < self.min_level:
            min_level = self.min_level
        return PrintStreamWrapper(self.stream, max_level=max_level, min_level=min_level)


class PackagePrinter:

    def __init__(self, stream: PrintStream, package: Package):
        self.package = package
        self.max_level = PrintLevel.max if self.package.enabled else PrintLevel.useless
        self.min_level = PrintLevel.min
        self.stream = PrintStreamWrapper(stream, max_level=self.max_level, min_level=self.min_level)

    def print_package(self, indent: int = 0):
        self.stream.print("Package [%s]" % self.package, indent=indent, level=self.stream.title)
        self.stream.print("name=%s" % self.package.app_name, indent=indent + 4, level=self.stream.normal)
        self.stream.print("userId=%s" % self.package.user_id, indent=indent + 4, level=self.stream.normal)
        self.stream.print("gids=%s" % self.package.gids, indent=indent + 4, level=self.stream.normal)
        self.stream.print("sourceDir=%s" % self.package.source_dir, indent=indent + 4, level=self.stream.normal)
        self.stream.print("versionCode=%s" % self.package.version_code, indent=indent + 4, level=self.stream.normal)
        self.stream.print("versionName=%s" % self.package.version_name, indent=indent + 4, level=self.stream.normal)
        self.stream.print("enabled=%s" % self.package.enabled, indent=indent + 4, level=self.stream.normal)
        self.stream.print("system=%s" % self.package.system, indent=indent + 4, level=self.stream.normal)
        self.stream.print("debuggable=%s" % self.package.debuggable, indent=indent + 4,
                          level=self.stream.dangerous if self.package.debuggable else self.stream.normal)
        self.stream.print("allowBackup=%s" % self.package.allow_backup, indent=indent + 4,
                          level=self.stream.dangerous if self.package.allow_backup else self.stream.normal)
        self.stream.print_line()

    def print_requested_permissions(self, indent: int = 4):
        if not utils.is_empty(self.package.requested_permissions):
            stream = self.stream.create(max_level=PrintLevel.normal)
            self.stream.print("RequestedPermissions:", indent=indent, level=self.stream.title)
            for permission in self.package.requested_permissions:
                self._print_permission(stream, permission, indent=indent + 4, identity="RequestedPermission")
            self.stream.print_line()

    def print_permissions(self, indent: int = 4):
        if not utils.is_empty(self.package.permissions):
            self.stream.print("Permissions:", indent=indent, level=self.stream.title)
            for permission in self.package.permissions:
                self._print_permission(self.stream, permission, indent=indent + 4, identity="Permission")
            self.stream.print_line()

    def print_activities(self, indent: int = 4):
        if not utils.is_empty(self.package.activities):
            self.stream.print("Activities:", indent=indent, level=self.stream.title)
            for activity in self.package.activities:
                self._print_component(self.stream, self.package, activity, indent=indent + 4, identity="Activity")
            self.stream.print_line()

    def print_services(self, indent: int = 4):
        if not utils.is_empty(self.package.services):
            self.stream.print("Services:", indent=indent, level=self.stream.title)
            for service in self.package.services:
                self._print_component(self.stream, self.package, service, indent=indent + 4, identity="Service")
            self.stream.print_line()

    def print_receivers(self, indent: int = 4):
        if not utils.is_empty(self.package.receivers):
            self.stream.print("Receivers:", indent=indent, level=self.stream.title)
            for receiver in self.package.receivers:
                self._print_component(self.stream, self.package, receiver, indent=indent + 4, identity="Receiver")
            self.stream.print_line()

    def print_providers(self, indent: int = 4):
        if not utils.is_empty(self.package.providers):
            self.stream.print("Providers:", indent=indent, level=self.stream.title)
            for provider in self.package.providers:
                self._print_component(self.stream, self.package, provider, indent=indent + 4, identity="Provider")
            self.stream.print_line()

    @classmethod
    def _print_permission(cls, stream: PrintStreamWrapper, permission: Permission, indent: int = 0,
                          identity: str = None):
        if permission.is_defined():
            stream.print("%s [%s] %s" % (identity, permission, permission.protection), indent=indent,
                         level=stream.dangerous if permission.is_dangerous() else stream.normal)

    @classmethod
    def _print_component(cls, stream: PrintStreamWrapper, package: Package, component: Component, indent: int = 0, identity: str = None):
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
        stream.print("%s [%s/%s] %s" % (identity, package, component, description), indent=indent, level=level)

        if isinstance(component, Activity) or isinstance(component, Service) or isinstance(component, Receiver):
            cls._print_permission(stream, component.permission, indent=indent + 4, identity="Permission")
        elif isinstance(component, Provider):
            stream.print("Authority [%s]" % component.authority, indent=indent + 4, level=level)
            cls._print_permission(stream, component.read_permission, indent=indent + 4,
                                  identity="ReadPermission")
            cls._print_permission(stream, component.write_permission, indent=indent + 4,
                                  identity="writePermission")
            for pattern in component.uri_permission_patterns:
                stream.print("UriPermissionPattern [%s]" % pattern, indent=indent + 4, level=level)
            for permission in component.path_permissions:
                stream.print("PathPermission [%s]" % permission, indent=indent + 4,
                             level=stream.dangerous if permission.is_dangerous() else stream.normal)
                cls._print_permission(stream, permission.read_permission, indent=indent + 8,
                                      identity="ReadPermission")
                cls._print_permission(stream, permission.write_permission, indent=indent + 8,
                                      identity="writePermission")

        if not utils.is_empty(component.intents):
            for intent in component.intents:
                cls._print_intent(stream, intent, indent=indent + 4, level=level)

    @classmethod
    def _print_intent(cls, stream: PrintStreamWrapper, intent: IntentFilter, indent: int = 0,
                      level: int = PrintLevel.normal):
        stream.print("IntentFilter:", indent=indent, level=level)
        for action in intent.actions:
            stream.print("Action [%s]" % action, indent=indent + 4, level=level)
        for category in intent.categories:
            stream.print("Category [%s]" % category, indent=indent + 4, level=level)
        for scheme in intent.data_schemes:
            stream.print("Scheme [%s]" % scheme, indent=indent + 4, level=level)
        for scheme in intent.data_scheme_specific_parts:
            stream.print("Scheme [%s]" % scheme, indent=indent + 4, level=level)
        for authority in intent.data_authorities:
            stream.print("Authority [%s]" % authority, indent=indent + 4, level=level)
        for path in intent.data_paths:
            stream.print("Path [%s]" % path, indent=indent + 4, level=level)
        for type in intent.data_types:
            stream.print("Type [%s]" % type, indent=indent + 4, level=level)


class Command(AndroidCommand):
    """
    Fetch application info
    """

    def init_arguments(self, parser: ArgumentParser) -> None:
        group = parser.add_mutually_exclusive_group()
        group.add_argument('-t', '--top', action='store_true', default=False,
                           help='fetch current running app only')
        group.add_argument('-a', '--all', action='store_true', default=False,
                           help='fetch all apps')
        group.add_argument('-p', '--packages', metavar="pkg", action='store', nargs='+', default=None,
                           help='fetch target apps only')
        group.add_argument('-u', '--uids', metavar="uid", action='store', nargs='+', type=int, default=None,
                           help='fetch apps with specified uids only')
        group.add_argument('--system', action='store_true', default=False,
                           help='fetch system apps only')
        group.add_argument('--non-system', action='store_true', default=False,
                           help='fetch non-system apps only')

        parser.add_argument('--simple', action='store_true', default=False,
                            help='display simple info only')
        parser.add_argument('--dangerous', action='store_true', default=False,
                            help='display dangerous permissions and components only')
        parser.add_argument('-o', '--order-by', metavar="field", action='store', nargs='+', default=['userId', 'name'],
                            choices=['name', 'appName', 'userId', 'sourceDir',
                                     'enabled', 'system', 'debuggable', 'allowBackup'],
                            help='order by target field')

    def run(self, args: Namespace) -> Optional[int]:
        device = args.device_picker.pick()

        if not utils.is_empty(args.packages):
            packages = device.get_packages(*args.packages, simple=args.simple)
        elif not utils.is_empty(args.uids):
            packages = device.get_packages_for_uid(*args.uids, simple=args.simple)
        elif args.system:
            packages = device.get_packages(system=True, simple=args.simple)
        elif args.non_system:
            packages = device.get_packages(system=False, simple=args.simple)
        elif args.all:
            packages = device.get_packages(simple=args.simple)
        else:
            packages = device.get_packages(device.get_current_package(), simple=args.simple)

        if not utils.is_empty(args.order_by):
            packages = sorted(packages, key=lambda x: [utils.get_item(x, k, default="") for k in args.order_by])

        min_level = PrintLevel.min
        if args.dangerous:
            min_level = PrintLevel.dangerous_normal
        stream = PrintStream(min_level=min_level)

        for package in packages:
            printer = PackagePrinter(stream, package)
            if not args.dangerous:
                printer.print_package()
                printer.print_requested_permissions()
                printer.print_permissions()
                printer.print_activities()
                printer.print_services()
                printer.print_receivers()
                printer.print_providers()
                continue

            if package.is_dangerous():
                printer.print_package()
                if package.has_dangerous_permission():
                    printer.print_permissions()
                if package.has_dangerous_activity():
                    printer.print_activities()
                if package.has_dangerous_service():
                    printer.print_services()
                if package.has_dangerous_receiver():
                    printer.print_receivers()
                if package.has_dangerous_provider():
                    printer.print_providers()

        return


command = Command()
if __name__ == "__main__":
    command.main()
