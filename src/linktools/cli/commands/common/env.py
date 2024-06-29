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
   /  oooooooooooooooo  .o.  oooo /,   `,"-----------
  / ==ooooooooooooooo==.o.  ooo= //   ,``--{)B     ,"
 /_==__==========__==_ooo__ooo=_/'   /___________,"
"""
import os
import sys
from typing import Any

from linktools import utils
from linktools.cli import subcommand, subcommand_argument, SubCommandWrapper, BaseCommandGroup, \
    iter_command_modules, commands
from linktools.cli.argparse import auto_complete
from linktools.utils import get_system, list2cmdline

DEFAULT_SHELL = "bash" if get_system() != "windows" else "powershell"


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
    Manage and configure the Linktools environment
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

    @subcommand("completion", help="generate shell auto complete script")
    @subcommand_argument("-s", "--shell", help="output code for the specified shell",
                         choices=["bash", "zsh", "tcsh", "fish", "powershell"])
    @subcommand_argument("--sync", action="store_true", help="sync complete script")
    def on_completion(self, shell: str = DEFAULT_SHELL, sync: bool = False):
        if not auto_complete:
            self.logger.warning("argcomplete module not found")
            return

        path = self.environ.get_data_path("scripts", f"completion_{self.environ.version}", create_parent=True)
        if not sync and os.path.exists(path):
            self.logger.info(f"Found complete script: {path}")
            print(utils.read_file(path, text=True), flush=True)
            return 0

        executables = []
        modules = {c.name: c for c in iter_command_modules(commands, onerror="warn")}
        for module in modules.values():
            if module.command:
                temp = module
                names = [module.command_name]
                while temp.parent_name in modules:
                    temp = modules[temp.parent_name]
                    names.append(temp.command_name)
                executable = "-".join(reversed(names))
                executables.append(executable)
                self.logger.info(f"Found executable: {executable}")

        result = auto_complete.shellcode(executables, shell=shell)
        utils.write_file(path, result)
        print(result, flush=True)

    @subcommand("alias", help="generate shell alias script")
    @subcommand_argument("-s", "--shell", help="output code for the specified shell",
                         choices=["bash", "zsh", "tcsh", "fish", "powershell"])
    @subcommand_argument("--sync", action="store_true", help="sync alias script")
    def on_alias(self, shell: str = DEFAULT_SHELL, sync: bool = False):
        path = self.environ.get_data_path("scripts", f"alias_{self.environ.version}", create_parent=True)
        if not sync and os.path.exists(path):
            self.logger.info(f"Found alias script: {path}")
            print(utils.read_file(path, text=True), flush=True)
            return 0

        lines = []
        modules = {c.name: c for c in iter_command_modules(commands, onerror="warn")}
        for module in modules.values():
            if module.command:
                temp = module
                names = [module.command_name]
                while temp.parent_name in modules:
                    temp = modules[temp.parent_name]
                    names.append(temp.command_name)
                executable = "-".join(reversed(names))
                cmdline = list2cmdline([sys.executable, "-m", module.module.__name__])
                self.logger.info(f"Found alias: {executable} -> {cmdline}")

                if shell in ("bash", "zsh"):
                    lines.append(f"alias {executable}='{cmdline}'")
                elif shell in ("tcsh", "fish"):
                    lines.append(f"alias {executable} '{cmdline}'")
                elif shell in ("powershell",):
                    lines.append(f"function __{executable}__ {{ {cmdline} $args }}")
                    lines.append(f"Set-Alias -Name {executable} -Value __{executable}__")

        result = os.linesep.join(lines)
        utils.write_file(path, result)
        print(result, flush=True)

    @subcommand("java", help="generate java environment script")
    @subcommand_argument("-s", "--shell", help="output code for the specified shell",
                         choices=["bash", "zsh", "tcsh", "fish", "powershell"])
    @subcommand_argument("version", metavar="VERSION", nargs="?",
                         help="java version, such as 11.0.23 / 17.0.11 / 22.0.1")
    def on_java_home(self, version: str = None, shell: str = DEFAULT_SHELL):
        from linktools.cli.commands.common import tools
        cmdline = list2cmdline([sys.executable, "-m", tools.__name__, "java"])

        java = self.environ.tools["java"]
        if version:
            java = java.copy(version=version)

        lines = []
        if shell in ("bash", "zsh"):
            lines.append(f"alias java='{cmdline}'")
            lines.append(f"export JAVA_CMDLINE=''")
            lines.append(f"export JAVA_VERSION='{java.get('version')}'")
            lines.append(f"export JAVA_HOME='{java.get('home_path')}'")
            lines.append(f"export PATH=\"$JAVA_HOME/bin:$PATH\"")
        elif shell in ("fish",):
            lines.append(f"alias java '{cmdline}'")
            lines.append(f"set -x JAVA_CMDLINE ''")
            lines.append(f"set -x JAVA_VERSION '{java.get('version')}'")
            lines.append(f"set -x JAVA_HOME '{java.get('home_path')}'")
            lines.append(f"set -x PATH \"$JAVA_HOME/bin\" \"$PATH\"")
        elif shell in ("tcsh",):
            lines.append(f"alias java '{cmdline}'")
            lines.append(f"setenv JAVA_CMDLINE ''")
            lines.append(f"setenv JAVA_VERSION '{java.get('version')}'")
            lines.append(f"setenv JAVA_HOME '{java.get('home_path')}'")
            lines.append(f"setenv PATH \"$JAVA_HOME/bin:$PATH\"")
        elif shell in ("powershell",):
            lines.append(f"function __tool_java__ {{ {cmdline} $args }}")
            lines.append(f"Set-Alias -Name java -Value __tool_java__")
            lines.append(f"$env:JAVA_CMDLINE=' '")
            lines.append(f"$env:JAVA_VERSION='{java.get('version')}'")
            lines.append(f"$env:JAVA_HOME='{java.get('home_path')}'")
            lines.append(f"$env:PATH=\"$env:JAVA_HOME\\bin;$env:PATH\"")

        result = os.linesep.join(lines)
        print(result, flush=True)

    @subcommand("clean", help="clean temporary files")
    @subcommand_argument("days", metavar="DAYS", nargs="?", help="expire days")
    def on_clean(self, days: int = 7):
        self.environ.clean_temp_files(days)


command = Command()
if __name__ == "__main__":
    command.main()
