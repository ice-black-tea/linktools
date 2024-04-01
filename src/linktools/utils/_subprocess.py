#!/usr/bin/env python3
# -*- coding:utf-8 -*-

import errno
import os
import queue
import subprocess
import threading
from typing import AnyStr, Tuple, Optional, IO, Callable, Any

from . import Timeout, timeoutable
from .._environ import environ
from ..decorator import cached_property


list2cmdline = subprocess.list2cmdline


class Output:
    STDOUT = 1
    STDERR = 2

    def __init__(self, stdout: IO[AnyStr], stderr: IO[AnyStr]):
        self._queue = queue.Queue()
        self._stdout_finished = None
        self._stdout_thread = None
        self._stderr_finished = None
        self._stderr_thread = None
        if stdout:
            self._stdout_finished = threading.Event()
            self._stdout_thread = threading.Thread(
                target=self._iter_lines,
                args=(stdout, self.STDOUT, self._stdout_finished,)
            )
            self._stdout_thread.daemon = True
            self._stdout_thread.start()
        if stderr:
            self._stderr_finished = threading.Event()
            self._stderr_thread = threading.Thread(
                target=self._iter_lines,
                args=(stderr, self.STDERR, self._stderr_finished,)
            )
            self._stderr_thread.daemon = True
            self._stderr_thread.start()

    @property
    def is_alive(self):
        if self._stdout_finished and not self._stdout_finished.is_set():
            return True
        if self._stderr_finished and not self._stderr_finished.is_set():
            return True
        return False

    def _iter_lines(self, io: IO[AnyStr], flag: int, event: threading.Event):
        try:
            while True:
                data = io.readline()
                if not data:
                    break
                self._queue.put((flag, data))
        except OSError as e:
            if e.errno != errno.EBADF:
                environ.logger.debug(f"Handle output error: {e}")
        finally:
            event.set()
            self._queue.put((None, None))

    def get_lines(self, timeout: Timeout):
        while self.is_alive:
            try:
                # 给个1秒超时时间防止有多个线程消费的时候死锁
                flag, data = self._queue.get(timeout=min(timeout.remain or 1, 1))
                if flag is not None:
                    yield flag, data
            except queue.Empty:
                if not timeout.check():
                    break

        while True:
            try:
                # 需要把剩余可消费的数据消费完
                flag, data = self._queue.get_nowait()
                if flag is not None:
                    yield flag, data
            except queue.Empty:
                break


class Process(subprocess.Popen):

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
                kwargs["cwd"] = environ.get_temp_dir(create=True)
        if "append_env" in kwargs:
            env = kwargs.pop("env", None)
            env = dict(env) if env else dict()
            env.update(kwargs.pop("append_env"))
            for key, value in os.environ.items():
                env.setdefault(key, value)
            kwargs["env"] = env

        args = [str(arg) for arg in args]
        environ.logger.debug(f"Exec cmdline: {list2cmdline(args)}")

        super().__init__(args, **kwargs)

    @timeoutable
    def call(self, timeout: Timeout = None) -> int:
        with self:
            try:
                return self.wait(timeout=timeout.remain)
            except Exception:
                self.kill()
                raise

    @timeoutable
    def call_as_daemon(self, timeout: Timeout = None) -> int:
        try:
            return self.wait(timeout=timeout.remain or .1)
        except subprocess.TimeoutExpired:
            return 0

    @timeoutable
    def check_call(self, timeout: Timeout = None) -> int:
        with self:
            try:
                retcode = self.wait(timeout=timeout.remain)
                if retcode:
                    raise subprocess.CalledProcessError(retcode, self.args)
                return retcode
            except:
                self.kill()
                raise

    @timeoutable
    def exec(
            self,
            timeout: Timeout = None,
            on_stdout: Callable[[str], Any] = None,
            on_stderr: Callable[[str], Any] = None
    ) -> Tuple[Optional[AnyStr], Optional[AnyStr]]:
        """
        执行命令
        :param timeout: 超时时间
        :param on_stdout: 把输出打印到logger中
        :param on_stderr: 把输出打印到logger中
        :return: 返回stdout输出内容
        """

        out = err = None

        if self.stdout or self.stderr:

            for flag, data in self._output.get_lines(timeout):
                if flag == self._output.STDOUT:
                    out = data if out is None else out + data
                    if on_stdout:
                        data = data.decode(errors="ignore") if isinstance(data, bytes) else data
                        data = data.rstrip()
                        if data:
                            on_stdout(data)

                elif flag == self._output.STDERR:
                    err = data if err is None else err + data
                    if on_stderr:
                        data = data.decode(errors="ignore") if isinstance(data, bytes) else data
                        data = data.rstrip()
                        if data:
                            on_stderr(data)
        else:

            try:
                self.wait(timeout.remain)
            except subprocess.TimeoutExpired:
                pass

        return out, err

    @cached_property
    def _output(self):
        return Output(self.stdout, self.stderr)
