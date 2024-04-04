#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
@author  : Hu Ji
@file    : container.py
@time    : 2024/3/21
@site    : https://github.com/ice-black-tea
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
from typing import Any

from linktools import utils
from linktools.cli import subcommand, subcommand_argument, SubCommandWrapper, BaseCommandGroup


class InitCommand(BaseCommandGroup):
    """
    initialize environment
    """

    @property
    def name(self) -> str:
        return "init"

    @subcommand("android", help="initialize android environment")
    def on_init_android(self):
        try:
            self.logger.info("initialize adb ...")
            self.environ.tools["adb"].prepare()
        except Exception as e:
            self.logger.warning(f"initialize adb failed: {e}")

        try:
            from linktools.frida.android import AndroidFridaServer
            self.logger.info("initialize android frida server ...")
            AndroidFridaServer.setup(abis=["arm", "arm64"])
        except Exception as e:
            self.logger.warning(f"initialize android frida server failed: {e}")

    @subcommand("ios", help="initialize ios environment")
    def on_init_ios(self):
        try:
            self.logger.info("initialize sib ...")
            self.environ.tools["sib"].prepare()
        except Exception as e:
            self.logger.warning(f"initialize sib failed: {e}")


class Command(BaseCommandGroup):
    """
    Linktools environment commands
    """

    def init_subcommands(self) -> Any:
        return [
            SubCommandWrapper(InitCommand()),
            self
        ]

    @subcommand("shell", help="run shell command")
    @subcommand_argument("-c", "--command", help="shell command")
    def on_shell(self, command: str = None):
        shell = self.environ.tools["shell"]
        if not shell.exists:
            raise NotImplementedError(f"Not found shell path")

        if command:
            process = utils.Process(command, shell=True)
            return process.call()

        process = shell.popen()
        return process.call()

    @subcommand("clean", help="clean temporary files")
    @subcommand_argument("days", metavar="DAYS", nargs="?", help="expire days")
    def on_clean_temp(self, days: int = 7):
        self.environ.clean_temp_files(days)


command = Command()
if __name__ == "__main__":
    command.main()
