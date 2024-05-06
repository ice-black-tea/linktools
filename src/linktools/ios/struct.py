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
   /  oooooooooooooooo  .o.  oooo /,   `,"-----------
  / ==ooooooooooooooo==.o.  ooo= //   ,``--{)B     ,"
 /_==__==========__==_ooo__ooo=_/'   /___________,"
"""

from .. import utils


class App:

    def __init__(self, obj: dict):
        self.bundle_id = utils.get_item(obj, "bundleId", type=str, default="")
        self.name = utils.get_item(obj, "name", type=str, default="")
        self.short_version = utils.get_item(obj, "shortVersion", type=str, default="")
        self.version = utils.get_item(obj, "version", type=str, default="")
        self.icon_base64 = utils.get_item(obj, "iconBase64", type=str, default="")

    def __repr__(self):
        return f"App<{self.bundle_id}>"


class Process:

    def __init__(self, obj: dict):
        self.pid = utils.get_item(obj, "pid", type=int, default=0)
        self.name = utils.get_item(obj, "name", type=str, default=0)
        self.real_app_name = utils.get_item(obj, "realAppName", type=str, default="")
        self.is_application = utils.get_item(obj, "isApplication", type=bool, default=0)
        self.start_date = utils.get_item(obj, "startDate", type=str, default="")

    def __repr__(self):
        return f"Process<{self.name}>"
