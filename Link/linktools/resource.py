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

from . import utils
from .decorator import singleton


@singleton
class Resource(object):

    def __init__(self):
        self._root_path = os.path.abspath(os.path.join(__file__, "..", "..", "resource"))
        self._configs = {}

    def get_config(self, path: str, *key: [str]):
        if path not in self._configs:
            with open(os.path.join(self._root_path, "config", path), "rt") as fd:
                self._configs[path] = json.load(fd)
        return utils.get_item(self._configs[path], *key)

    def get_persist_path(self, *paths: [str]):
        return os.path.join(self._root_path, "persist", *paths)

    def get_cache_path(self, *paths: [str]):
        return os.path.join(self._root_path, "cache", *paths)

    def get_cache_dir(self, *paths: [str], create: bool = False):
        path = self.get_cache_path(*paths)
        if create and not os.path.exists(path):
            os.makedirs(path)
        return path


resource = Resource()
