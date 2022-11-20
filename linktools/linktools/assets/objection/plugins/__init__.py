#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
@author  : Hu Ji
@file    : __init__.py.py 
@time    : 2022/11/20
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

from objection.utils.plugin import Plugin

from linktools import resource, __name__ as module_name

__description__ = f"{module_name} plugin"

from linktools.frida import FridaEvalCode


class LinktoolsPlugin(Plugin):

    def __init__(self, ns):
        self.script_path = resource.get_asset_path("frida.js")
        super().__init__(__file__, ns, {
            'meta': f'"{module_name}',
            'commands': {
                'load': {
                    'meta': 'load',
                    'exec': self.load_scripts
                }
            }
        })
        self.inject()

    def load_scripts(self, args: list):
        scripts = []
        for arg in args:
            scripts.append(FridaEvalCode(arg).to_dict())
        self.api.load_scripts(scripts)


namespace = 'lt'
plugin = LinktoolsPlugin
