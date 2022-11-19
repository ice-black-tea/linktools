#!/usr/bin/env python3
# -*- coding:utf-8 -*-

# Datetime  : 2022/11/11 下午5:45
# Author    : HuJi <jihu.hj@alibaba-inc.com>
import os
import subprocess
from typing import Union

from ._logging import get_logger

_logger = get_logger("subprocess")


def popen(*args, **kwargs) -> subprocess.Popen:
    """
    打开进程
    :param args: 参数
    :return: 子进程
    """
    capture_output = kwargs.pop("capture_output", False)
    if capture_output is True:
        if kwargs.get("stdout") is not None or kwargs.get("stderr") is not None:
            raise ValueError("stdout and stderr arguments may not be used "
                             "with capture_output.")
        kwargs["stdout"] = subprocess.PIPE
        kwargs["stderr"] = subprocess.PIPE
    if "cwd" not in kwargs:
        kwargs["cwd"] = os.getcwd()
    if "shell" not in kwargs:
        kwargs["shell"] = False
    if "append_env" in kwargs:
        env = os.environ.copy()
        env.update(kwargs.pop("env", {}))
        env.update(kwargs.pop("append_env"))
        kwargs["env"] = env
    _logger.debug(f"Exec cmdline: {' '.join(args)}")
    return subprocess.Popen(args, **kwargs)


def exec(*args, **kwargs) -> (subprocess.Popen, Union[str, bytes], Union[str, bytes]):
    """
    执行命令
    :param args: 参数
    :return: 子进程
    """

    input = kwargs.pop("input", None)
    timeout = kwargs.pop("timeout", None)
    daemon = kwargs.pop("daemon", None)

    capture_output = kwargs.pop("capture_output", False)
    output_to_logger = kwargs.pop("output_to_logger", False)
    ignore_errors = kwargs.pop("ignore_errors", False)

    if capture_output is True or output_to_logger is True:
        if kwargs.get("stdout") is not None or kwargs.get("stderr") is not None:
            raise ValueError("stdout and stderr arguments may not be used "
                             "with capture_output or output_to_logger.")
        kwargs["stdout"] = subprocess.PIPE
        kwargs["stderr"] = subprocess.PIPE

    process, out, err = None, None, None
    try:
        process = popen(*args, **kwargs)
        out, err = process.communicate(
            input=input,
            timeout=timeout or .1 if daemon else timeout
        )
    except Exception as e:
        if ignore_errors:
            _logger.debug(f"Ignore error: {e}")
        elif daemon and isinstance(e, subprocess.TimeoutExpired):
            pass
        else:
            raise e
    finally:
        if process and not daemon:
            process.kill()

    if output_to_logger is True:
        if out:
            message = out.decode(errors="ignore") if isinstance(out, bytes) else out
            _logger.info(message.rstrip())
        if err:
            message = err.decode(errors="ignore") if isinstance(err, bytes) else err
            _logger.error(message.rstrip())

    return process, out, err
