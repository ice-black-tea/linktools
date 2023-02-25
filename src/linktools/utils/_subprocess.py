#!/usr/bin/env python3
# -*- coding:utf-8 -*-

import errno
import os
import queue
import subprocess
import threading
from typing import Union, AnyStr, Tuple, Optional, IO

from . import Timeout
from .._environ import environ
from .._logging import get_logger
from ..decorator import cached_property

_logger = get_logger("utils.subprocess")

list2cmdline = subprocess.list2cmdline


class Output:
    FLAG_STDOUT = 1
    FLAG_STDERR = 2

    def __init__(self, stdout: IO[AnyStr], stderr: IO[AnyStr]):
        self._queue = queue.Queue()
        self._stdout_thread = None
        self._stderr_thread = None
        if stdout:
            self._stdout_thread = threading.Thread(
                target=self._iter_lines,
                args=(self.FLAG_STDOUT, os.dup(stdout.fileno()),)
            )
            self._stdout_thread.daemon = True
            self._stdout_thread.start()
        if stderr:
            self._stderr_thread = threading.Thread(
                target=self._iter_lines,
                args=(self.FLAG_STDERR, os.dup(stderr.fileno()),)
            )
            self._stderr_thread.daemon = True
            self._stderr_thread.start()

    def _iter_lines(self, flag, fd):
        try:
            with os.fdopen(fd) as fd:
                for data in iter(fd.readline, ""):
                    self._queue.put((flag, data))
        except OSError as e:
            if e.errno != errno.EBADF:
                _logger.debug(f"Handle output error: {e}")
        finally:
            self._queue.put((None, None))

    def read_lines(self, timeout: Union[float, Timeout] = None):
        if not isinstance(timeout, Timeout):
            timeout = Timeout(timeout)
        while True:
            try:
                flag, data = self._queue.get(timeout=timeout.remain)
                if flag is None:
                    if self._stdout_thread and self._stdout_thread.is_alive():
                        pass
                    elif self._stderr_thread and self._stderr_thread.is_alive():
                        pass
                    else:
                        break
                yield flag, data
            except queue.Empty:
                break


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

    @cached_property
    def _output(self):
        return Output(self.stdout, self.stderr)

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

        out = err = None

        try:
            if self.stdout is None and self.stderr is None:
                self.wait(timeout.remain if isinstance(timeout, Timeout) else timeout)
                return out, err
        except subprocess.TimeoutExpired:
            pass

        for flag, data in self._output.read_lines(timeout):
            if flag == self._output.FLAG_STDOUT:
                out = data if out is None else out + data
                if log_stdout:
                    data = data.decode(errors="ignore") if isinstance(data, bytes) else data
                    data = data.rstrip()
                    if data:
                        _logger.info(data)

            elif flag == self._output.FLAG_STDERR:
                err = data if err is None else err + data
                if log_stderr:
                    data = data.decode(errors="ignore") if isinstance(data, bytes) else data
                    data = data.rstrip()
                    if data:
                        _logger.error(data)

        return out, err
