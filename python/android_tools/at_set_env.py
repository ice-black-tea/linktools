#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
@author  : Hu Ji
@file    : at_set_env.py
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

import os
import platform
import re
import sys
import subprocess
import shutil

if platform.system() == "Windows":
    if sys.hexversion <= 0x03000000:
        # noinspection PyUnresolvedReferences
        import _winreg as winreg
    else:
        # noinspection PyUnresolvedReferences
        import winreg
pass


class user_env:
    """
    用户环境变量
    """

    _system = platform.system()

    def __init__(self):
        """
        初始化
        """
        if self.is_windows():
            self.root = winreg.HKEY_CURRENT_USER
            self.sub_key = 'Environment'
        elif self.is_linux():
            self.bash_file = os.path.expanduser("~/.bashrc")
            self.bash_file_bak = self.bash_file + ".bak"
        elif self.is_macos():
            self.bash_file = os.path.expanduser("~/.bash_profile")
            self.bash_file_bak = self.bash_file + ".bak"

    def get(self, key: str, default: str = "") -> str:
        """
        获取环境变量
        :param key:
        :param default:
        :return:
        """
        value = default
        if self.is_windows():
            reg_key = winreg.OpenKey(self.root, self.sub_key, 0, winreg.KEY_READ)
            try:
                value, _ = winreg.QueryValueEx(reg_key, key)
            except WindowsError:
                pass
        else:
            value = os.getenv(key, default)
        return value

    def set(self, key: str, value: str) -> None:
        """
        设置环境变量
        :param key: 键
        :param value: 值
        """
        key = key.replace("\"", "\\\"")
        value = value.replace("\"", "\\\"")

        if self.is_windows():
            command = "setx \"%s\" \"%s\"" % (key, value)
            subprocess.call(command, stdout=subprocess.PIPE)

        elif self.is_linux() or self.is_macos():
            command_begin = "\n#-#-#-#-#-#-#-#-#-#-#-#-# written by user_env #-#-#-#-#-#-#-#-#-#-#-#-# %s\n" % key
            command_end = "\n#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-# %s\n" % key
            command = "export \"%s\"=\"%s\"" % (key, value)
            command = command_begin + command + command_end

            bash_command = ""
            if os.path.exists(self.bash_file):
                with open(self.bash_file, "r") as fd:
                    bash_command = fd.read()
                shutil.copyfile(self.bash_file, self.bash_file_bak)

            result = re.search(r"%s.+%s" % (command_begin, command_end), bash_command)
            if result is not None:
                span = result.span()
                bash_command = bash_command[:span[0]] + command + bash_command[span[1]:]
            else:
                bash_command = bash_command + command

            with open(self.bash_file, "w") as fd:
                fd.write(bash_command)

    def is_windows(self) -> bool:
        return self._system == "Windows"

    def is_linux(self) -> bool:
        return self._system == "Linux"

    def is_macos(self) -> bool:
        return self._system == "Darwin"


if __name__ == '__main__':

    tools_key = "ANDROID_TOOLS_PATH"
    tools_path = os.path.abspath(os.path.dirname(__file__))

    env = user_env()
    env.set(tools_key, tools_path)
    if env.is_windows():
        path_env = env.get("PATH")
        if tools_key not in path_env:
            path_env = "%s;%%%s%%" % (path_env, tools_key)
            env.set("PATH", path_env)
    else:
        env.set("PATH",  "$PATH:$%s" % tools_key)
