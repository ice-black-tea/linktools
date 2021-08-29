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

from ._config import Config, create_default_config
from ._tools import GeneralTools
from ._resource import Resource


config: Config = utils.LazyLoad(create_default_config)
tools: GeneralTools = utils.LazyLoad(GeneralTools)
resource: Resource = utils.LazyLoad(Resource)
