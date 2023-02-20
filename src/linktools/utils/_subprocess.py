#!/usr/bin/env python3
# -*- coding:utf-8 -*-
import asyncio
import os
import queue
import subprocess
import threading
from typing import Union, AnyStr, IO, Tuple, Callable, Optional

from . import Timeout
from ._asyncio import get_event_loop_thread
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

        class Buffer:

            def __init__(self, io: IO[AnyStr]):
                self._io = io
                self._queue = queue.Queue() if io is not None else None

            @property
            def io(self):
                return self._io

            def read(self) -> AnyStr:
                buffer = None
                if self._queue is not None:
                    while not self._queue.empty():
                        data = self._queue.get_nowait()
                        if buffer is not None:
                            buffer += data
                        else:
                            buffer = data
                return buffer

            def __call__(self, data: AnyStr):
                if self._queue:
                    self._queue.put(data)

        class OutBuffer(Buffer):

            def __call__(self, data: AnyStr):
                super().__call__(data)
                if log_stdout:
                    if isinstance(data, bytes):
                        data = data.decode(errors="ignore")
                    data = data.rstrip()
                    if data:
                        _logger.info(data.rstrip())

        class ErrBuffer(Buffer):

            def __call__(self, data: AnyStr):
                super().__call__(data)
                if log_stderr:
                    if isinstance(data, bytes):
                        data = data.decode(errors="ignore")
                    data = data.rstrip()
                    if data:
                        _logger.error(data.rstrip())

        async def check_alive():
            while self.poll() is None and not cancel_event.is_set():
                await asyncio.sleep(.1)

        async def iter_lines(io: IO[AnyStr], callback: Callable[[AnyStr], None]):
            try:
                loop = asyncio.get_running_loop()
                stream_reader = asyncio.StreamReader()
                stream_reader_protocol = asyncio.StreamReaderProtocol(stream_reader)
                await loop.connect_read_pipe(lambda: stream_reader_protocol, io)
                while not stream_reader.at_eof():
                    data = await stream_reader.readline()
                    callback(data)
            except Exception as e:
                _logger.debug(f"Read stream error: {e}")

        async def handle_output():
            try:
                tasks = []
                if out_buffer.io:
                    tasks.append(iter_lines(out_buffer.io, out_buffer))
                if err_buffer.io:
                    tasks.append(iter_lines(err_buffer.io, err_buffer))
                if tasks:
                    tasks.append(check_alive())
                    done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
                    if pending:
                        for task in pending:
                            task.cancel()
                        await asyncio.wait(pending, return_when=asyncio.ALL_COMPLETED)
            except Exception as e:
                _logger.debug(f"Read stream error: {e}")
            finally:
                finish_event.set()

        cancel_event = threading.Event()
        finish_event = threading.Event()

        out_buffer = OutBuffer(self.stdout)
        err_buffer = ErrBuffer(self.stderr)

        try:
            thread = get_event_loop_thread()
            thread.call_task_soon(handle_output())
            self.wait(timeout.remain if isinstance(timeout, Timeout) else timeout)
        except subprocess.TimeoutExpired:
            pass
        finally:
            cancel_event.set()
            finish_event.wait()

        return out_buffer.read(), err_buffer.read()
