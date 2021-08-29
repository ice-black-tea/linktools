#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
@author  : Hu Ji
@file    : resource.py 
@time    : 2018/12/01
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
import os


class Resource(object):

    def __init__(self):
        self._resource_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "resource"))

    def get_persist_path(self, *paths: [str]):
        return os.path.join(self._resource_path, "persist", *paths)

    # noinspection PyMethodMayBeStatic
    def get_data_path(self, *paths: [str]):
        from . import config
        return os.path.join(config["SETTINGS_DATA_PATH"], *paths)

    def get_data_dir(self, *paths: [str], create: bool = False):
        path = self.get_data_path(*paths)
        if create and not os.path.exists(path):
            os.makedirs(path)
        return path

    # noinspection PyMethodMayBeStatic
    def get_temp_path(self, *paths: [str]):
        from . import config
        return os.path.join(config["SETTINGS_TEMP_PATH"], *paths)

    def get_temp_dir(self, *paths: [str], create: bool = False):
        path = self.get_temp_path(*paths)
        if create and not os.path.exists(path):
            os.makedirs(path)
        return path
