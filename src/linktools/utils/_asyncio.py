#!/usr/bin/env python3
# -*- coding:utf-8 -*-

import asyncio
import atexit
import threading
from typing import Optional, Callable, Any, Coroutine

from .._logging import get_logger
from ..decorator import singleton

_logger = get_logger("utils.asyncio")


@singleton
class EventLoopThread(threading.Thread):

    def __init__(self):

        def run():
            self._loop = asyncio.new_event_loop()
            event.set()
            self._loop.run_forever()

        super().__init__(target=run)

        event = threading.Event()
        self.daemon = True
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self.start()
        event.wait()
        atexit.register(self.stop)

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
        return self._loop


def get_event_loop_thread():
    return EventLoopThread()
