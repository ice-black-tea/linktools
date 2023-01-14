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

__all__ = ("Resource",)

import os

from .decorator import cached_property
from ._environ import config


class Resource(object):

    def __init__(self, root_path: str):
        self._root_path = root_path

    def get_asset_path(self, *paths: [str]):
        return self._get_path(self._root_path, "assets", *paths, create=False, create_parent=False)

    def get_data_path(self, *paths: [str], create_parent: bool = False):
        return self._get_path(self._data_path, *paths, create=False, create_parent=create_parent)

    def get_data_dir(self, *paths: [str], create: bool = False):
        return self._get_path(self._data_path, *paths, create=create, create_parent=False)

    def get_temp_path(self, *paths: [str], create_parent: bool = False):
        return self._get_path(self._temp_path, *paths, create=False, create_parent=create_parent)

    def get_temp_dir(self, *paths: [str], create: bool = False):
        return self._get_path(self._temp_path, *paths, create=create, create_parent=False)

    @cached_property
    def _data_path(self):
        path = config["SETTING_DATA_PATH"]
        if not path:
            path = os.path.join(config["SETTING_STORAGE_PATH"], "data")
        return path

    @cached_property
    def _temp_path(self):
        path = config["SETTING_TEMP_PATH"]
        if not path:
            path = os.path.join(config["SETTING_STORAGE_PATH"], "temp")
        return path

    @classmethod
    def _get_path(cls, root_path: str, *paths: [str], create: bool = False, create_parent: bool = False):
        target_path = parent_path = os.path.abspath(root_path)
        for path in paths:
            target_path = os.path.abspath(os.path.join(parent_path, path))
            if target_path == parent_path or not cls.is_child_path(parent_path, target_path):
                raise Exception(f"Unsafe path \"{path}\"")
            parent_path = target_path
        dir_path = None
        if create:
            dir_path = target_path
        elif create_parent:
            dir_path = os.path.dirname(target_path)
        if dir_path is not None:
            if not os.path.exists(dir_path):
                os.makedirs(dir_path)
        return target_path

    @classmethod
    def is_child_path(cls, parent, child):
        return parent == os.path.commonpath([parent, child])
