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
from typing import Any, Optional

import click
from objection.state.app import app_state
from objection.utils.plugin import Plugin

from linktools import resource, __name__ as module_name
from linktools.frida import FridaEvalCode
from linktools.frida.app import FridaScript, FridaScriptHandler, FridaSession

__description__ = f"{module_name} plugin"


class LinktoolsPlugin(Plugin, FridaScriptHandler):

    def __init__(self, ns):
        self._script: Optional[FridaScript] = None
        self.script_path = resource.get_asset_path("frida.js")

        super().__init__(__file__, ns, {
            'meta': f'"{module_name}',
            'commands': {
                'eval': {
                    'meta': 'eval code',
                    'exec': self.eval_code
                }
            }
        })

        self.inject()

        if app_state.should_debug():
            self.eval_code([
                "Log.setLevel(Log.DEBUG);"
            ])

    def eval_code(self, args: list):
        self.api.load_scripts([
            FridaEvalCode(arg).to_dict() for arg in args
        ])

    def on_message_handler(self, message, data):
        if not self._script:
            self._script = FridaScript(
                FridaSession(self.session),
                self.script
            )
        return self.on_script_message(
            self._script, message, data
        )

    def on_script_log(self, script: FridaScript, level: str, message: Any, data: Any):
        if level == "info":
            click.secho(f'[info] ({namespace}) {message}')
        elif level == "warning":
            click.secho(f'[warning] ({namespace}) {message}', fg="yellow")
        elif level == "error":
            click.secho(f'[error] ({namespace}) {message}', fg="red")
        elif app_state.should_debug():
            click.secho(f'[debug] ({namespace}) {message}', dim=True)


namespace = 'lt'
plugin = LinktoolsPlugin
