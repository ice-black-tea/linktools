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

from .decorator import cached_property


class Resource(object):

    @cached_property
    def _resource_path(self):
        return os.path.abspath(os.path.join(os.path.dirname(__file__), "resource"))

    @cached_property
    def _data_path(self):
        from . import config
        path = config["SETTING_DATA_PATH"]
        if path is None or len(path) == 0:
            path = os.path.join(config["SETTING_STORAGE_PATH"], "data")
        return path

    @cached_property
    def _temp_path(self):
        from . import config
        path = config["SETTING_TEMP_PATH"]
        if path is None or len(path) == 0:
            path = os.path.join(config["SETTING_STORAGE_PATH"], "temp")
        return path

    def get_persist_path(self, *paths: [str]):
        return os.path.join(self._resource_path, *paths)

    def get_data_path(self, *paths: [str]):
        return os.path.join(self._data_path, *paths)

    def get_data_dir(self, *paths: [str], create: bool = False):
        path = self.get_data_path(*paths)
        if create and not os.path.exists(path):
            os.makedirs(path)
        return path

    def get_temp_path(self, *paths: [str]):
        return os.path.join(self._temp_path, *paths)

    def get_temp_dir(self, *paths: [str], create: bool = False):
        path = self.get_temp_path(*paths)
        if create and not os.path.exists(path):
            os.makedirs(path)
        return path
