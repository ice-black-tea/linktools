#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
@author  : Hu Ji
@file    : environment.py
@time    : 2020/03/01
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
import subprocess
import sys

from .version import __name__


class UserEnviron:
    """
    用户环境变量
    """

    _begin_template = "\n# {key} begin, created by ##name##, do not modify! \n".replace("##name##", __name__)
    _end_template = "\n# {key} end \n"

    def __init__(self):
        """
        初始化
        """
        self._winreg = None
        self._bash_file = None
        self.platform_name = platform.system().lower()
        if self.is_windows:
            self.root = self.winreg.HKEY_CURRENT_USER
            self.sub_key = 'Environment'
        elif self.is_linux:
            self.bash_file = "~/.bashrc"
        elif self.is_darwin:
            self.bash_file = "~/.bash_profile"
        else:
            self.raise_platform_error()

    @property
    def bash_file(self):
        return self._bash_file

    @bash_file.setter
    def bash_file(self, path):
        if not self.is_darwin and not self.is_linux:
            self.raise_platform_error()
        self._bash_file = os.path.expanduser(path)

    @property
    def bak_bash_file(self):
        return self.bash_file

    @property
    def winreg(self):
        if self._winreg is not None:
            return self._winreg
        if not self.is_windows:
            self.raise_platform_error()
        if sys.hexversion <= 0x03000000:
            import _winreg as winreg
        else:
            import winreg
        self._winreg = winreg
        return self._winreg

    def get(self, key, default=""):  # -> str:
        """
        获取环境变量
        :param key:
        :param default:
        :return:
        """
        value = default
        if self.is_windows:
            reg_key = self.winreg.OpenKey(self.root, self.sub_key, 0, self.winreg.KEY_READ)
            try:
                value, _ = self.winreg.QueryValueEx(reg_key, key)
            except WindowsError:
                pass
        else:
            value = os.getenv(key, default)
        return value

    def set(self, key, value):  # -> None:
        """
        设置环境变量
        :param key: 键
        :param value: 值
        """
        key = key.replace("\"", "\\\"")
        value = value.replace("\"", "\\\"")

        if self.is_windows:
            command = "setx \"{key}\" \"{value}\"".format(key=key, value=value)
            subprocess.call(command, stdout=subprocess.PIPE)

        elif self.is_linux or self.is_darwin:
            command_begin = self._begin_template.format(key=key)
            command_end = self._end_template.format(key=key)
            command = "export \"{key}\"=\"{value}\"".format(key=key, value=value)
            command = command_begin + command + command_end

            bash_command = ""
            if os.path.exists(self.bash_file):
                with open(self.bash_file, "r") as fd:
                    bash_command = fd.read()

            result = re.search(r"{begin}.+{end}".format(begin=command_begin, end=command_end), bash_command)
            if result is not None:
                span = result.span()
                bash_command = bash_command[:span[0]] + command + bash_command[span[1]:]
            else:
                bash_command = bash_command + command

            with open(self.bash_file, "w") as fd:
                fd.write(bash_command)

    def delete(self, key):  # -> None:
        """
        删除环境变量
        :param key: 键
        """
        if self.is_windows:
            reg_key = self.winreg.OpenKey(self.root, self.sub_key, 0, self.winreg.KEY_WRITE)
            try:
                self.winreg.DeleteValue(reg_key, key)
            except WindowsError as e:
                pass
        elif self.is_linux or self.is_darwin:
            command_begin = self._begin_template.format(key=key)
            command_end = self._end_template.format(key=key)

            if os.path.exists(self.bash_file):
                with open(self.bash_file, "r") as fd:
                    bash_command = fd.read()

                result = re.search(r"{begin}.+{end}".format(begin=command_begin, end=command_end), bash_command)
                if result is not None:
                    span = result.span()
                    bash_command = bash_command[:span[0]] + bash_command[span[1]:]

                with open(self.bash_file, "w") as fd:
                    fd.write(bash_command)

    @property
    def is_windows(self) -> bool:
        return self.platform_name == "windows"

    @property
    def is_linux(self) -> bool:
        return self.platform_name == "linux"

    @property
    def is_darwin(self) -> bool:
        return self.platform_name == "darwin"

    def raise_platform_error(self):
        raise Exception("{platform} is not supported".format(platform=self.platform_name))
