#!/usr/bin/env python3
# -*- coding:utf-8 -*-

import errno
import os
import subprocess
import threading
from typing import Union, AnyStr, Tuple, Optional

from . import Timeout, ignore_error
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

    def call(self, timeout: Union[float, Timeout] = None) -> int:
        with self:
            try:
                return self.wait(
                    timeout=timeout.remain if isinstance(timeout, Timeout) else timeout
                )
            except Exception:
                self.kill()
                raise

    def call_as_daemon(self, timeout: Union[float, Timeout] = None) -> int:
        try:
            return self.wait(
                timeout=(timeout.remain if isinstance(timeout, Timeout) else timeout) or .1
            )
        except subprocess.TimeoutExpired:
            return 0

    def check_call(self, timeout: Union[float, Timeout] = None) -> int:
        with self:
            try:
                retcode = self.wait(
                    timeout=timeout.remain if isinstance(timeout, Timeout) else timeout
                )
                if retcode:
                    raise subprocess.CalledProcessError(retcode, self.args)
                return retcode
            except:
                self.kill()
                raise

    def run(self, timeout: Union[float, Timeout] = None, log_stdout: bool = False, log_stderr: bool = False) \
            -> Tuple[Optional[AnyStr], Optional[AnyStr]]:
        """
        执行命令
        :param timeout: 超时时间
        :param log_stdout: 把输出打印到logger中
        :param log_stderr: 把输出打印到logger中
        :return: 返回stdout输出内容
        """

        if self.poll() is not None:
            return None, None

        class Output:

            def __init__(self, fd):
                self._fd = fd
                self._data = None

            @property
            def fd(self):
                return self._fd

            @property
            def data(self):
                return self._data

            def __call__(self, data: AnyStr):
                if self._data is not None:
                    self._data += data
                else:
                    self._data = data

        class Stdout(Output):

            def __call__(self, data: AnyStr):
                super().__call__(data)
                if log_stdout:
                    if isinstance(data, bytes):
                        data = data.decode(errors="ignore")
                    data = data.rstrip()
                    if data:
                        _logger.info(data.rstrip())

        class Stderr(Output):

            def __call__(self, data: AnyStr):
                super().__call__(data)
                if log_stderr:
                    if isinstance(data, bytes):
                        data = data.decode(errors="ignore")
                    data = data.rstrip()
                    if data:
                        _logger.error(data.rstrip())

        def handle_output(output: Output):
            try:
                with os.fdopen(output.fd) as fd:
                    for data in iter(fd.readline, ""):
                        output(data)
            except OSError as e:
                if e.errno != errno.EBADF:
                    _logger.debug(f"Handle output error: {e}")

        threads = []
        stdout = stderr = None

        try:
            if self.stdout:
                stdout = Stdout(os.dup(self.stdout.fileno()))
                threads.append(threading.Thread(target=handle_output, args=(stdout,)))

            if self.stderr:
                stderr = Stderr(os.dup(self.stdout.fileno()))
                threads.append(threading.Thread(target=handle_output, args=(stderr,)))

            for thread in threads:
                thread.start()
            self.wait(timeout.remain if isinstance(timeout, Timeout) else timeout)

        except subprocess.TimeoutExpired:
            pass

        finally:
            if stdout:
                ignore_error(os.close, stdout.fd)
            if stderr:
                ignore_error(os.close, stderr.fd)
            for thread in threads:
                thread.join()

        return stdout.data if stdout else None, \
               stderr.data if stderr else None
