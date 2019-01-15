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

from .utils import utils


class resource(object):
    _res_path = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "resource"))
    _config_path = os.path.join(_res_path, ".config")
    _config_data = None

    @staticmethod
    def get_config(*key: [str]):
        if not hasattr(resource, "config"):
            with open(resource._config_path, "rt") as fd:
                resource.config = json.load(fd)
        if utils.empty(key):
            return resource.config
        return utils.item(resource.config, *key)

    # @staticmethod
    # def save_config(config):
    #     with open(resource._config_path, "wt") as fd:
    #         json.dump(fd, config, sort_keys=True, indent=4)

    @staticmethod
    def res_path(*paths: [str]):
        path = os.path.join(resource._res_path, *paths)
        dirname = os.path.dirname(path)
        if not os.path.exists(dirname):
            os.makedirs(dirname)
        return path

    @staticmethod
    def download_path(*paths: [str]):
        path = os.path.join(resource._res_path, "download", *paths)
        dirname = os.path.dirname(path)
        if not os.path.exists(dirname):
            os.makedirs(dirname)
        return path
