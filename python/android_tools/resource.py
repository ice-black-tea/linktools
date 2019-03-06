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
import json
import os

from .decorator import singleton
from .utils import Utils


@singleton
class Resource(object):
    _res_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "resource")

    def __init__(self):
        self.config = None

    def get_path(self, *paths: [str]):
        return os.path.join(self._res_path, *paths)

    def get_config(self, *key: [str]):
        if self.config is None:
            with open(self.get_path(".config"), "rt") as fd:
                self.config = json.load(fd)
        if Utils.is_empty(key):
            return self.config
        return Utils.get_item(self.config, *key)

    def get_store_path(self, *paths: [str], create_dir: bool = False, create_file: bool = False):
        path = os.path.join(self._res_path, "store", *paths)
        if create_dir or create_file:
            dirname = os.path.dirname(path)
            if not os.path.exists(dirname):
                os.makedirs(dirname)
        if create_file:
            if not os.path.exists(path):
                open(path, 'a').close()
        return path


resource = Resource()
