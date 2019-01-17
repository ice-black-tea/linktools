#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
@author  : Hu Ji
@file    : struct.py
@time    : 2019/01/11
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
from .utils import Utils


class PatternMatcher:

    def __init__(self, obj: dict):
        self.path = Utils.get_item(obj, "path", type=str, default="")
        self.type = Utils.get_item(obj, "type", type=str, default="literal")

    def __str__(self):
        return "path=%s, type=%s" % (self.path, self.type)


class PathPermission(PatternMatcher):

    def __init__(self, obj: dict):
        super().__init__(obj)
        self.readPermission = Utils.get_item(obj, "readPermission", type=Permission, default={})
        self.writePermission = Utils.get_item(obj, "writePermission", type=Permission, default={})

    def is_dangerous(self):
        return self.readPermission.is_dangerous() or self.writePermission.is_dangerous()


class AuthorityEntry:

    def __init__(self, obj: dict):
        self.host = Utils.get_item(obj, "host", type=str, default="")
        self.port = Utils.get_item(obj, "port", type=int, default=0)

    def __str__(self):
        return "host=%s, port=%s" % (self.host, self.port)


class IntentFilter:

    def __init__(self, obj: dict):
        self.actions = Utils.get_array_item(obj, "actions", type=str, default=[])
        self.categories = Utils.get_array_item(obj, "categories", type=str, default=[])
        self.dataSchemes = Utils.get_array_item(obj, "dataSchemes", type=str, default=[])
        self.dataSchemeSpecificParts = Utils.get_array_item(obj, "dataSchemeSpecificParts", type=PatternMatcher, default=[])
        self.dataAuthorities = Utils.get_array_item(obj, "dataAuthorities", type=AuthorityEntry, default=[])
        self.dataPaths = Utils.get_array_item(obj, "dataPaths", type=PatternMatcher, default=[])
        self.dataTypes = Utils.get_array_item(obj, "dataTypes", type=str, default=[])


class Permission:

    _default = None

    @staticmethod
    def default():
        if Permission._default is None:
            Permission._default = Permission({"name": "", "protection": "normal"})
        return Permission._default

    def __init__(self, obj: dict):
        self.name = Utils.get_item(obj, "name", type=str, default="")
        self.protection = Utils.get_item(obj, "protection", type=str, default="normal")

    def is_defined(self):
        return not Utils.is_empty(self.name)

    def is_dangerous(self):
        return self.protection in ["dangerous", "normal"]

    def __str__(self):
        return self.name


class Component:

    def __init__(self, obj: dict):
        self.name = Utils.get_item(obj, "name", type=str, default="")
        self.exported = Utils.get_item(obj, "exported", type=bool, default=False)
        self.enabled = Utils.get_item(obj, "enabled", type=bool, default=False)
        self.intents = Utils.get_array_item(obj, "intents", type=IntentFilter, default=[])

    def is_dangerous(self):
        return True

    def __str__(self):
        return self.name


class Activity(Component):

    def __init__(self, obj: dict):
        super().__init__(obj)
        self.permission = Utils.get_item(obj, "permission", type=Permission, default=Permission.default())

    def is_dangerous(self):
        return self.exported and self.permission.is_dangerous()


class Service(Component):

    def __init__(self, obj: dict):
        super().__init__(obj)
        self.permission = Utils.get_item(obj, "permission", type=Permission, default=Permission.default())

    def is_dangerous(self):
        return self.exported and self.permission.is_dangerous()


class Receiver(Component):

    def __init__(self, obj: dict):
        super().__init__(obj)
        self.permission = Utils.get_item(obj, "permission", type=Permission, default=Permission.default())

    def is_dangerous(self):
        return self.exported and self.permission.is_dangerous()


class Provider(Component):

    def __init__(self, obj: dict):
        super().__init__(obj)
        self.authority = Utils.get_item(obj, "authority", type=str, default="")
        self.readPermission = Utils.get_item(obj, "readPermission", type=Permission, default=Permission.default())
        self.writePermission = Utils.get_item(obj, "writePermission", type=Permission, default=Permission.default())
        self.uriPermissionPatterns = Utils.get_array_item(obj, "uriPermissionPatterns", type=PatternMatcher, default=[])
        self.pathPermissions = Utils.get_array_item(obj, "pathPermissions", type=PathPermission, default=[])

    def is_dangerous(self):
        if not self.exported:
            return False
        if self.readPermission.is_dangerous() or self.writePermission.is_dangerous():
            return True
        for pathPermission in self.pathPermissions:
            if pathPermission.is_dangerous():
                return True
        return False


class Package:

    def __init__(self, obj: dict):
        self.name = Utils.get_item(obj, "name", type=str, default="")
        self.appName = Utils.get_item(obj, "appName", type=str, default="")
        self.userId = Utils.get_item(obj, "userId", type=str, default="")
        self.gids = Utils.get_item(obj, "gids", type=str, default=[])
        self.sourceDir = Utils.get_item(obj, "sourceDir", type=str, default="")
        self.versionCode = Utils.get_item(obj, "versionCode", type=str, default="")
        self.versionName = Utils.get_item(obj, "versionName", type=str, default="")
        self.enabled = Utils.get_item(obj, "enabled", type=bool, default=False)
        self.system = Utils.get_item(obj, "system", type=bool, default=False)
        self.debuggable = Utils.get_item(obj, "debuggable", type=bool, default=False)
        self.allowBackup = Utils.get_item(obj, "allowBackup", type=bool, default=False)

        self.requestedPermissions = Utils.get_array_item(obj, "requestedPermissions", type=Permission, default=[])
        self.permissions = Utils.get_array_item(obj, "permissions", type=Permission, default=[])
        self.activities = Utils.get_array_item(obj, "activities", type=Activity, default=[])
        self.services = Utils.get_array_item(obj, "services", type=Service, default=[])
        self.receivers = Utils.get_array_item(obj, "receivers", type=Receiver, default=[])
        self.providers = Utils.get_array_item(obj, "providers", type=Provider, default=[])

    def is_dangerous(self):
        return self.debuggable or self.allowBackup or \
            self.has_dangerous_permission() or \
            self.has_dangerous_activity() or \
            self.has_dangerous_service() or \
            self.has_dangerous_receiver() or \
            self.has_dangerous_provider()

    def has_dangerous_permission(self):
        for permission in self.permissions:
            if permission.is_dangerous():
                return True
        return False

    def has_dangerous_activity(self):
        for activity in self.activities:
            if activity.is_dangerous():
                return True
        return False

    def has_dangerous_service(self):
        for service in self.services:
            if service.is_dangerous():
                return True
        return False

    def has_dangerous_receiver(self):
        for receiver in self.receivers:
            if receiver.is_dangerous():
                return True
        return False

    def has_dangerous_provider(self):
        for provider in self.providers:
            if provider.is_dangerous():
                return True
        return False

    def __str__(self):
        return self.name
