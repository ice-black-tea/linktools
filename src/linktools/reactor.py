#!/usr/bin/env python3
# -*- coding:utf-8 -*-
import abc
import asyncio
import atexit
import functools
import threading
import time
import traceback
from collections import deque
from typing import Optional, Callable, Any, Coroutine

from ._environ import environ
from .utils import InterruptableEvent

_logger = environ.get_logger("reactor")


class Stoppable(abc.ABC):

    @abc.abstractmethod
    def stop(self):
        pass

    def __enter__(self):
        return self

    def __exit__(self, *args, **kwargs):
        self.stop()


class Reactor(Stoppable):
    """
    Code stolen from frida_tools.application.Reactor
    """

    def __init__(self, on_stop=None, on_error=None):
        self._running = False
        self._on_stop = on_stop
        self._on_error = on_error
        self._pending = deque([])
        self._lock = threading.Lock()
        self._cond = threading.Condition(self._lock)
        self._worker = None

    def is_running(self) -> "bool":
        with self._lock:
            return self._running

    def run(self):
        with self._lock:
            self._running = True
        self._worker = threading.Thread(target=self._run)
        self._worker.daemon = True
        self._worker.start()

    def _run(self):
        running = True
        while running:
            now = time.time()
            work = None
            timeout = None
            with self._lock:
                for item in self._pending:
                    (f, when) = item
                    if now >= when:
                        work = f
                        self._pending.remove(item)
                        break
                if len(self._pending) > 0:
                    timeout = max([min(map(lambda item: item[1], self._pending)) - now, 0])
                previous_pending_length = len(self._pending)

            if work is not None:
                try:
                    work()
                except (KeyboardInterrupt, EOFError) as e:
                    if self._on_error is not None:
                        self._on_error(e, traceback.format_exc())
                    self.stop()
                except BaseException as e:
                    if self._on_error is not None:
                        self._on_error(e, traceback.format_exc())

            with self._lock:
                if self._running and len(self._pending) == previous_pending_length:
                    self._cond.wait(timeout)
                running = self._running

        if self._on_stop is not None:
            self._on_stop()

    def stop(self, delay: float = None):
        self.schedule(self._stop, delay)

    def _stop(self):
        with self._lock:
            self._running = False

    def schedule(self, fn: Callable[[], any], delay: float = None):
        now = time.time()
        if delay is not None:
            when = now + delay
        else:
            when = now
        with self._lock:
            self._pending.append((functools.partial(self._work, fn), when))
            self._cond.notify()

    def _work(self, fn: Callable[[], any]):
        fn()

    def wait(self, timeout=5):
        assert self._worker
        self._worker.join(timeout)
        if self._worker.is_alive():
            _logger.warning("Worker did not finish normally")

    def __enter__(self):
        self.run()

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.stop()
        self.wait()


class ReactorThread(threading.Thread):

    def __init__(self):
        def run():
            self._loop = asyncio.new_event_loop()
            event.set()
            self._loop.run_forever()

        super().__init__(target=run)

        event = InterruptableEvent()
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
