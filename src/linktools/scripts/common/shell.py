#!/usr/bin/env python3
# -*- coding:utf-8 -*-

# Author    : HuJi <jihu.hj@alibaba-inc.com>
# Datetime  : 2021/12/16 3:23 下午
# User      : huji
# Product   : PyCharm
# Project   : link
import os
from argparse import ArgumentParser
from typing import Optional

from linktools import utils, tools


class Script(utils.ConsoleScript):

    def _get_description(self) -> str:
        return "shell wrapper"

    def _add_arguments(self, parser: ArgumentParser) -> None:
        pass

    def _run(self, args: [str]) -> Optional[int]:
        if tools.system in ["darwin", "linux"]:
            bash_path = "/bin/bash"
            if "SHELL" in os.environ:
                bash_path = os.environ["SHELL"]
        elif tools.system in ["windows"]:
            bash_path = "C:\\WINDOWS\\system32\\cmd.exe"
            if "ComSpec" in os.environ:
                bash_path = os.environ["ComSpec"]
        else:
            raise NotImplementedError(f"unsupported system {tools.system}")

        if not os.path.exists(bash_path):
            raise NotImplementedError(f"file {bash_path} does not exist")

        process = utils.Popen(bash_path, *args)
        return process.call()


script = Script()
if __name__ == "__main__":
    script.main()
