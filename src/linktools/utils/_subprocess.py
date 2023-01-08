#!/usr/bin/env python3
# -*- coding:utf-8 -*-

# Datetime  : 2022/11/11 下午5:45
# Author    : HuJi <jihu.hj@alibaba-inc.com>
import os
import subprocess
from typing import AnyStr

from . import _utils as utils
from .._environ import environ
from .._logging import get_logger

_logger = get_logger("utils.subprocess")

list2cmdline = subprocess.list2cmdline


class Popen(subprocess.Popen):

    def __init__(self, *args, **kwargs):
        capture_output = kwargs.pop("capture_output", False)
        if capture_output is True:
            if kwargs.get("stdout") is not None or kwargs.get("stderr") is not None:
                raise ValueError("stdout and stderr arguments may not be used "
                                 "with capture_output.")
            kwargs["stdout"] = subprocess.PIPE
            kwargs["stderr"] = subprocess.PIPE
        if "cwd" not in kwargs:
            try:
                kwargs["cwd"] = os.getcwd()
            except FileNotFoundError:
                kwargs["cwd"] = environ.resource.get_temp_dir()
        if "append_env" in kwargs:
            env = os.environ.copy()
            env.update(kwargs.pop("env", {}))
            env.update(kwargs.pop("append_env"))
            kwargs["env"] = env

        args = [str(arg) for arg in args]
        _logger.debug(f"Exec cmdline: {' '.join(args)}")

        super().__init__(args, **kwargs)

    def call(self, timeout: float = None) -> int:
        with self:
            try:
                return self.wait(timeout=timeout)
            except Exception:
                self.kill()
                raise

    def call_as_daemon(self, timeout: float = None) -> int:
        try:
            return self.wait(timeout=timeout or .1)
        except subprocess.TimeoutExpired:
            return 0

    def check_call(self, timeout: float = None) -> int:
        with self:
            try:
                retcode = self.wait(timeout=timeout)
                if retcode:
                    raise subprocess.CalledProcessError(retcode, self.args)
                return retcode
            except:
                self.kill()
                raise
