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
import pathlib
import sys
from typing import Any

from linktools import utils, Tool
from linktools.cli import subcommand, subcommand_argument, SubCommandWrapper, BaseCommandGroup, \
    iter_module_commands, commands, iter_entry_point_commands
from linktools.cli.argparse import auto_complete
from linktools.decorator import cached_property
from linktools.metadata import __ep_group__

DEFAULT_SHELL = "bash" if utils.get_system() != "windows" else "powershell"


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
            from linktools.frida import FridaAndroidServer
            self.logger.info("initialize android frida server ...")
            FridaAndroidServer.setup(abis=["arm", "arm64"])
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

    @cached_property
    def stub_path(self) -> pathlib.Path:
        return self.environ.get_data_path(
            "env",
            f"stub_v{self.environ.version}",
            utils.get_md5(sys.executable)
        )

    @cached_property
    def alias_path(self) -> pathlib.Path:
        return self.environ.get_data_path(
            "env",
            f"alias_v{self.environ.version}",
            utils.get_md5(sys.executable)
        )

    @subcommand("shell", help="run shell command")
    @subcommand_argument("-c", "--command", help="shell command")
    def on_shell(self, command: str = None):
        shell = self.environ.tools["shell"]
        if not shell.exists:
            raise NotImplementedError(f"Not found shell path")

        paths = os.environ.get("PATH", "").split(os.pathsep)
        stub_path = str(self.stub_path)
        if stub_path not in paths:
            paths.append(stub_path)
        stub_path = str(self.environ.tools.stub_path)
        if stub_path not in paths:
            paths.append(stub_path)

        env = dict(PATH=os.pathsep.join(paths))
        if command:
            return utils.popen(command, shell=True, append_env=env).call()

        return shell.popen(append_env=env).call()

    @subcommand("alias", help="generate shell alias script")
    @subcommand_argument("-s", "--shell", help="output code for the specified shell",
                         choices=["bash", "zsh", "tcsh", "fish", "powershell"])
    @subcommand_argument("--reload", action="store_true", help="reload alias script")
    def on_alias(self, shell: str = DEFAULT_SHELL, reload: bool = False):
        alias_path = self.alias_path
        alias_path.parent.mkdir(parents=True, exist_ok=True)
        if not reload and os.path.exists(alias_path):
            self.logger.info(f"Found alias script: {alias_path}")
            print(utils.read_file(alias_path, text=True), flush=True)
            return 0

        tools_path = self.environ.tools.stub_path
        stub_path = self.stub_path
        stub_path.mkdir(parents=True, exist_ok=True)
        utils.clear_directory(stub_path)

        executables = []
        command_infos = {
            command_info.id: command_info
            for command_info in (
                *iter_module_commands(commands, onerror="warn"),
                *iter_entry_point_commands(__ep_group__, onerror="warn")
            )
        }
        for command_info in command_infos.values():
            if command_info.command:
                temp = command_info
                names = [command_info.command_name]
                while temp.parent_id in command_infos:
                    temp = command_infos[temp.parent_id]
                    names.append(temp.command_name)
                executable = "-".join(reversed(names))
                executables.append(executable)
                Tool.create_stub_file(
                    stub_path / Tool.get_stub_name(executable),
                    utils.list2cmdline([sys.executable, "-m", command_info.module]),
                    system=self.environ.system
                )
                self.logger.info(f"Found alias: {executable} -> {command_info.module}")

        lines = []
        if auto_complete:
            try:
                self.logger.info("Generate completion script ...")
                lines.append(auto_complete.shellcode(executables, shell=shell))
            except:
                pass

        if shell in ("bash", "zsh"):
            lines.append(f"export PATH=\"$PATH:{stub_path}:{tools_path}\"")
        elif shell in ("fish",):
            lines.append(f"set -x PATH \"$PATH\" \"{stub_path}\" \"{tools_path}\"")
        elif shell in ("tcsh",):
            lines.append(f"setenv PATH \"$PATH:{stub_path}:{tools_path}\"")
        elif shell in ("powershell",):
            lines.append(f"$env:PATH=\"$env:PATH;{stub_path}:{tools_path}\"")

        result = os.linesep.join(lines)
        utils.write_file(alias_path, result)
        print(result, flush=True)

    @subcommand("completion", help="generate shell auto complete script (deprecated)")
    @subcommand_argument("-s", "--shell", help="output code for the specified shell",
                         choices=["bash", "zsh", "tcsh", "fish", "powershell"])
    @subcommand_argument("--reload", action="store_true", help="reload complete script")
    def on_completion(self, shell: str = DEFAULT_SHELL, reload: bool = False):
        self.logger.warning("Not support generate completion script, already integrated into alias subcommand")

    @subcommand("java", help="generate java environment script")
    @subcommand_argument("-s", "--shell", help="output code for the specified shell",
                         choices=["bash", "zsh", "tcsh", "fish", "powershell"])
    @subcommand_argument("version", metavar="VERSION", nargs="?",
                         help="java version, such as 11.0.23 / 17.0.11 / 22.0.1")
    def on_java_home(self, version: str = None, shell: str = DEFAULT_SHELL):
        from linktools.cli import stub
        cmdline = utils.list2cmdline([sys.executable, "-m", stub.__name__, "tool", "java"])

        java = self.environ.tools["java"]
        if version:
            java = java.copy(version=version)

        lines = []
        if shell in ("bash", "zsh"):
            lines.append(f"alias java='{cmdline}'")
            lines.append(f"export JAVA_VERSION='{java.get('version')}'")
            lines.append(f"export JAVA_HOME='{java.get('home_path')}'")
            lines.append(f"export PATH=\"$JAVA_HOME/bin:$PATH\"")
        elif shell in ("fish",):
            lines.append(f"alias java '{cmdline}'")
            lines.append(f"set -x JAVA_VERSION '{java.get('version')}'")
            lines.append(f"set -x JAVA_HOME '{java.get('home_path')}'")
            lines.append(f"set -x PATH \"$JAVA_HOME/bin\" \"$PATH\"")
        elif shell in ("tcsh",):
            lines.append(f"alias java '{cmdline}'")
            lines.append(f"setenv JAVA_VERSION '{java.get('version')}'")
            lines.append(f"setenv JAVA_HOME '{java.get('home_path')}'")
            lines.append(f"setenv PATH \"$JAVA_HOME/bin:$PATH\"")
        elif shell in ("powershell",):
            lines.append(f"function __tool_java__ {{ {cmdline} $args }}")
            lines.append(f"Set-Alias -Name java -Value __tool_java__")
            lines.append(f"$env:JAVA_VERSION='{java.get('version')}'")
            lines.append(f"$env:JAVA_HOME='{java.get('home_path')}'")
            lines.append(f"$env:PATH=\"$env:JAVA_HOME\\bin;$env:PATH\"")

        result = os.linesep.join(lines)
        print(result, flush=True)

    @subcommand("clean", help="clean temporary files")
    @subcommand_argument("days", metavar="DAYS", nargs="?", help="expire days")
    def on_clean(self, days: int = 7):
        self.environ.clean_temp_files(expire_days=days)


command = Command()
if __name__ == "__main__":
    command.main()
