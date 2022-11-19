#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
@author  : Hu Ji
@file    : argparser.py 
@time    : 2020/03/07
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

__all__ = ("ArgumentParser", "range_type")

import argparse
import logging

from ._environ import logger
from .version import __version__


def range_type(min, max):

    def wrapper(o):
        value = int(o)
        if min <= value <= max:
            return value
        raise argparse.ArgumentTypeError("value not in range %s-%s" % (min, max))

    return wrapper


class ArgumentParser(argparse.ArgumentParser):

    def __init__(self,
                 conflict_handler="resolve",
                 **kwargs):
        super().__init__(
            conflict_handler=conflict_handler,
            **kwargs
        )

        class VerboseAction(argparse.Action):

            def __init__(self,
                         option_strings,
                         dest=argparse.SUPPRESS,
                         default=argparse.SUPPRESS,
                         help=None):
                super(VerboseAction, self).__init__(
                    option_strings=option_strings,
                    dest=dest,
                    default=default,
                    nargs=0,
                    help=help)

            def __call__(self, parser, namespace, values, option_string=None):
                logger.setLevel(logging.DEBUG)

        self.add_argument("--version", action="version", version="%(prog)s " + __version__)
        self.add_argument("-v", "--verbose", action=VerboseAction, help="increase log verbosity")
