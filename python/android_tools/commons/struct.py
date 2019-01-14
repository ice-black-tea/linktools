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
from .utils import utils


class pattern_matcher:

    def __init__(self, obj: dict):
        self.path = utils.item(obj, "path", type=str, default="")
        self.type = utils.item(obj, "type", type=str, default="literal")

    def __str__(self):
        return "path=%s, type=%s" % (self.path, self.type)


class path_permission(pattern_matcher):

    def __init__(self, obj: dict):
        super().__init__(obj)
        self.readPermission = utils.item(obj, "readPermission", type=permission, default={})
        self.writePermission = utils.item(obj, "writePermission", type=permission, default={})

    def is_dangerous(self):
        return self.readPermission.is_dangerous() or self.writePermission.is_dangerous()


class authority_entry:

    def __init__(self, obj: dict):
        self.host = utils.item(obj, "host", type=str, default="")
        self.port = utils.item(obj, "port", type=int, default=0)

    def __str__(self):
        return "host=%s, port=%s" % (self.host, self.port)


class intent_filter:

    def __init__(self, obj: dict):
        self.actions = utils.array_item(obj, "actions", type=str, default=[])
        self.categories = utils.array_item(obj, "categories", type=str, default=[])
        self.dataSchemes = utils.array_item(obj, "dataSchemes", type=str, default=[])
        self.dataSchemeSpecificParts = utils.array_item(obj, "dataSchemeSpecificParts", type=pattern_matcher, default=[])
        self.dataAuthorities = utils.array_item(obj, "dataAuthorities", type=authority_entry, default=[])
        self.dataPaths = utils.array_item(obj, "dataPaths", type=pattern_matcher, default=[])
        self.dataTypes = utils.array_item(obj, "dataTypes", type=str, default=[])


class permission:

    _default = None

    @staticmethod
    def default():
        if permission._default is None:
            permission._default = permission({"name": "", "protection": "normal"})
        return permission._default

    def __init__(self, obj: dict):
        self.name = utils.item(obj, "name", type=str, default="")
        self.protection = utils.item(obj, "protection", type=str, default="normal")

    def is_defined(self):
        return not utils.empty(self.name)

    def is_dangerous(self):
        return self.protection in ["dangerous", "normal"]

    def __str__(self):
        return self.name


class component:

    def __init__(self, obj: dict):
        self.name = utils.item(obj, "name", type=str, default="")
        self.exported = utils.item(obj, "exported", type=bool, default=False)
        self.enabled = utils.item(obj, "enabled", type=bool, default=False)
        self.intents = utils.array_item(obj, "intents", type=intent_filter, default=[])

    def is_dangerous(self):
        return True

    def __str__(self):
        return self.name


class activity(component):

    def __init__(self, obj: dict):
        super().__init__(obj)
        self.permission = utils.item(obj, "permission", type=permission, default=permission.default())

    def is_dangerous(self):
        return self.exported and self.permission.is_dangerous()


class service(component):

    def __init__(self, obj: dict):
        super().__init__(obj)
        self.permission = utils.item(obj, "permission", type=permission, default=permission.default())

    def is_dangerous(self):
        return self.exported and self.permission.is_dangerous()


class receiver(component):

    def __init__(self, obj: dict):
        super().__init__(obj)
        self.permission = utils.item(obj, "permission", type=permission, default=permission.default())

    def is_dangerous(self):
        return self.exported and self.permission.is_dangerous()


class provider(component):

    def __init__(self, obj: dict):
        super().__init__(obj)
        self.authority = utils.item(obj, "authority", type=str, default="")
        self.readPermission = utils.item(obj, "readPermission", type=permission, default=permission.default())
        self.writePermission = utils.item(obj, "writePermission", type=permission, default=permission.default())
        self.uriPermissionPatterns = utils.array_item(obj, "uriPermissionPatterns", type=pattern_matcher, default=[])
        self.pathPermissions = utils.array_item(obj, "pathPermissions", type=path_permission, default=[])

    def is_dangerous(self):
        if not self.exported:
            return False
        if self.readPermission.is_dangerous() or self.writePermission.is_dangerous():
            return True
        for pathPermission in self.pathPermissions:
            if pathPermission.is_dangerous():
                return True
        return False


class package:

    def __init__(self, obj: dict):
        self.name = utils.item(obj, "name", type=str, default="")
        self.appName = utils.item(obj, "appName", type=str, default="")
        self.userId = utils.item(obj, "userId", type=str, default="")
        self.gids = utils.item(obj, "gids", type=str, default=[])
        self.sourceDir = utils.item(obj, "sourceDir", type=str, default="")
        self.versionCode = utils.item(obj, "versionCode", type=str, default="")
        self.versionName = utils.item(obj, "versionName", type=str, default="")
        self.enabled = utils.item(obj, "enabled", type=bool, default=False)
        self.system = utils.item(obj, "system", type=bool, default=False)
        self.debuggable = utils.item(obj, "debuggable", type=bool, default=False)
        self.allowBackup = utils.item(obj, "allowBackup", type=bool, default=False)

        self.requestedPermissions = utils.array_item(obj, "requestedPermissions", type=permission, default=[])
        self.permissions = utils.array_item(obj, "permissions", type=permission, default=[])
        self.activities = utils.array_item(obj, "activities", type=activity, default=[])
        self.services = utils.array_item(obj, "services", type=service, default=[])
        self.receivers = utils.array_item(obj, "receivers", type=receiver, default=[])
        self.providers = utils.array_item(obj, "providers", type=provider, default=[])

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
