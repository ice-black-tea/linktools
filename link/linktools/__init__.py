#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
@author  : Hu Ji
@file    : __init__.py
@time    : 2018/11/25
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
import sys

if (sys.version_info.major, sys.version_info.minor) < (3, 5):
    raise Exception("only supports python 3.5 or higher")

from . import utils, logger
from .version import __name__, __version__, __author__, __email__, __url__
from .argparser import ArgumentParser

from ._config import Config
from ._tools import GeneralTools
from ._resource import Resource


def _get_config():
    import json
    import os
    cfg = Config()
    config_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "configs"))
    for root, dirs, files in os.walk(config_path):
        for name in files:
            if name.endswith(".py"):
                cfg.from_pyfile(os.path.join(root, name))
            elif name.endswith(".json"):
                cfg.from_file(os.path.join(root, name), load=json.load)
    return cfg


config: Config = utils.LazyLoad(_get_config)
tools: GeneralTools = utils.LazyLoad(GeneralTools)
resource: Resource = utils.LazyLoad(Resource)
