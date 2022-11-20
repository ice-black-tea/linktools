#!/usr/bin/env python3
# -*- coding:utf-8 -*-

# Datetime  : 2022/11/11 下午5:45
# Author    : HuJi <jihu.hj@alibaba-inc.com>
import os
import subprocess
from typing import AnyStr

from .._logging import get_logger

_logger = get_logger("utils.subprocess")


class Popen(subprocess.Popen):

    def __init__(self, *args, **kwargs):
        capture_output = kwargs.pop("capture_output", False)
        if capture_output is True:
            if kwargs.get('stdout') is not None or kwargs.get('stderr') is not None:
                raise ValueError('stdout and stderr arguments may not be used '
                                 'with capture_output.')
            kwargs["stdout"] = subprocess.PIPE
            kwargs["stderr"] = subprocess.PIPE
        if "cwd" not in kwargs:
            kwargs["cwd"] = os.getcwd()
        if kwargs.get("shell", False):
            raise ValueError("shell argument is not allowed.")
        if "append_env" in kwargs:
            env = os.environ.copy()
            env.update(kwargs.pop("env", {}))
            env.update(kwargs.pop("append_env"))
            kwargs["env"] = env

        super().__init__([str(arg) for arg in args], **kwargs)
        _logger.debug(f"Exec cmdline: {' '.join(self.args)}")

    def call(self, timeout: float = None, daemon: bool = False) -> int:
        with self:
            try:
                return self.wait(timeout=timeout or .1 if daemon else timeout)
            except Exception as e:
                if daemon and isinstance(e, subprocess.TimeoutExpired):
                    return 0
                self.kill()
                raise

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

    def communicate(self, input: AnyStr = None, timeout: float = None, ignore_errors=False) -> (AnyStr, AnyStr):
        """
        执行命令，简单包装了一下communicate
        :param input:
        :param timeout:
        :param ignore_errors:
        :return: out, err
        """

        out, err = None, None
        try:
            out, err = super().communicate(
                input=input,
                timeout=timeout,
            )
        except Exception as e:
            if ignore_errors:
                _logger.debug(f"Ignore error: {e}")
            else:
                raise e
        finally:
            self.kill()

        return out, err
