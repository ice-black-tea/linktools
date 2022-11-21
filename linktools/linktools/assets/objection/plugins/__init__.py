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
import json

import click
from objection.state.app import app_state
from objection.utils.plugin import Plugin

from linktools import resource, __name__ as module_name, utils
from linktools.frida import FridaEvalCode

__description__ = f"{module_name} plugin"


def log_debug(message):
    if app_state.should_debug():
        click.secho(f'[debug] ({namespace}) {message}', dim=True)


def log_info(message):
    click.secho(f'[info] ({namespace}) {message}')


def log_warning(message):
    click.secho(f'[warning] ({namespace}) {message}')


def log_error(message):
    click.secho(f'[error] ({namespace}) {message}')


class LinktoolsPlugin(Plugin):

    def __init__(self, ns):
        self.script_path = resource.get_asset_path("frida.js")
        self.on_message_handler = self.on_message
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
        scripts = []
        for arg in args:
            scripts.append(FridaEvalCode(arg).to_dict())
        self.api.load_scripts(scripts)

    def on_message(self, message: object, data: object):

        if utils.get_item(message, "type") == "send":

            payload = utils.get_item(message, "payload")
            if payload is not None and isinstance(payload, dict):

                log = payload.pop("log", None)
                if log is not None:
                    self.on_script_log(log, data)

                event = payload.pop("event", None)
                if event is not None:
                    self.on_script_event(event, data)

                while len(payload) > 0:
                    key, value = payload.popitem()
                    self.on_script_send(key, value, data)

            # 字符串类型，直接输出
            if not utils.is_empty(payload):
                log_info(payload)

        elif utils.get_item(message, "type") == "error":

            if utils.is_contain(message, "stack"):
                log_error(utils.get_item(message, "stack"))
            else:
                log_error(message)

        else:
            log_warning(message)

    def on_script_log(self, log: dict, data: object):
        level = log.get("level") or "debug"
        message = log.get("message")

        log_fn = log_debug
        if level == "info":
            log_fn = log_info
        if level == "warning":
            log_fn = log_warning
        if level == "error":
            log_fn = log_error

        if not utils.is_empty(message):
            log_fn(message)

    def on_script_event(self, message: object, data: object):
        log_info(
            f"{json.dumps(message, indent=2, ensure_ascii=False)}",
        )

    def on_script_send(self, type: str, message: object, data: object):
        log_debug(
            f"type={type}, message={message}"
        )


namespace = 'lt'
plugin = LinktoolsPlugin
