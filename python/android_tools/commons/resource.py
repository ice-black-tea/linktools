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


class _resource(object):

    def __init__(self):
        self.res_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "resource")
        self.config_path = os.path.join(self.res_path, ".config")

    def get_config(self):
        with open(self.config_path, "rt") as fd:
            config = json.load(fd)
        return config

    def save_config(self, config):
        with open(self.config_path, "wt") as fd:
            json.dump(fd, config)

    def get_path(self, name):
        return os.path.join(self.res_path, name)
