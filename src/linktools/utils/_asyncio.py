#!/usr/bin/env python3
# -*- coding:utf-8 -*-

import asyncio
import threading
from typing import Optional, Callable, Any, Coroutine

from .._logging import get_logger

_logger = get_logger("utils.asyncio")

event_loop_thread: Optional["EventLoopThread"] = None
event_loop_thread_lock = threading.RLock()


class EventLoopThread(threading.Thread):

    def __init__(self):
        super().__init__()
        self.daemon = True
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._event = threading.Event()

    def run(self):
        loop = self._loop = asyncio.new_event_loop()
        self._event.set()
        loop.run_forever()

    def stop(self):
        loop = self.get_event_loop()
        loop.call_soon_threadsafe(lambda: loop.stop())

    def call_soon(self, callback: Callable[..., Any]):
        loop = self.get_event_loop()
        return loop.call_soon_threadsafe(callback)

    def call_task_soon(self, coro: Coroutine):
        loop = self.get_event_loop()
        return loop.call_soon_threadsafe(lambda: loop.create_task(coro))

    def get_event_loop(self) -> asyncio.AbstractEventLoop:
        if self._loop is None:
            self._event.wait()
        assert self._loop is not None
        return self._loop


def get_event_loop_thread():
    global event_loop_thread
    global event_loop_thread_lock
    if event_loop_thread is None:
        with event_loop_thread_lock:
            if event_loop_thread is None:
                event_loop_thread = EventLoopThread()
                event_loop_thread.start()
    return event_loop_thread
