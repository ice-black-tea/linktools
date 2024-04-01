#!/usr/bin/env python3
# -*- coding:utf-8 -*-

import getpass
import os
import shutil
from argparse import ArgumentParser, Namespace
from typing import Optional

from linktools import utils, environ
from linktools.cli import BaseCommand


class Command(BaseCommand):
    """
    Shell with environment variables already initialized
    """

    def main(self, *args, **kwargs) -> None:
        self.environ.config.set_default("SHOW_LOG_LEVEL", False)
        self.environ.config.set_default("SHOW_LOG_TIME", False)
        return super().main(*args, **kwargs)

    def __init__(self):
        self._shell_path = None
        if environ.system in ["darwin", "linux"]:
            try:
                import pwd
                self._shell_path = pwd.getpwnam(getpass.getuser()).pw_shell
            except:
                self._shell_path = shutil.which("bash") or shutil.which("sh")
            if "SHELL" in os.environ:
                self._shell_path = os.environ["SHELL"]
        elif environ.system in ["windows"]:
            self._shell_path = shutil.which("powershell") or shutil.which("cmd")
            if "ComSpec" in os.environ:
                self._shell_path = os.environ["ComSpec"]

    def init_arguments(self, parser: ArgumentParser) -> None:
        parser.add_argument("-c", "--command", action="store", default=None, help="shell command")

    def run(self, args: Namespace) -> Optional[int]:
        if args.command:
            process = utils.Process(args.command, shell=True)
            return process.call()

        if not self._shell_path or not os.path.exists(self._shell_path):
            raise NotImplementedError(f"unsupported system {environ.system}")

        process = utils.Process(self._shell_path)
        return process.call()


command = Command()
if __name__ == "__main__":
    command.main()
