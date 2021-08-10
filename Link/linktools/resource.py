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

_root_path = os.path.abspath(os.path.join(__file__, "..", "..", "resource"))
_configs = {}


def get_config(path: str, *key: [str]):
    if path not in _configs:
        with open(os.path.join(_root_path, "config", path), "rt") as fd:
            _configs[path] = json.load(fd)
    return utils.get_item(_configs[path], *key)


def get_persist_path(*paths: [str]):
    return os.path.join(_root_path, "persist", *paths)


def get_cache_path(*paths: [str]):
    return os.path.join(_root_path, "cache", *paths)


def get_cache_dir(*paths: [str], create: bool = False):
    path = get_cache_path(*paths)
    if create and not os.path.exists(path):
        os.makedirs(path)
    return path
