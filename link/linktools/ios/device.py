#!/usr/bin/env python3
# -*- coding:utf-8 -*-

# Author    : HuJi <jihu.hj@alibaba-inc.com>
# Datetime  : 2022/2/25 6:30 PM
# User      : huji
# Product   : PyCharm
# Project   : link
import asyncio
import threading
from asyncio import StreamReader, StreamWriter
from typing import Union, Optional

import tidevice

from linktools import get_logger

logger = get_logger("ios.device")

MuxError = tidevice.MuxError


class Usbmux(tidevice.Usbmux):
    __default_usbmux = tidevice.Usbmux()

    @classmethod
    def set_default(cls, usbmux: Union["Usbmux", str]):
        if isinstance(usbmux, str):
            cls.__default_usbmux = Usbmux(usbmux)
        elif isinstance(usbmux, Usbmux):
            cls.__default_usbmux = usbmux

    @classmethod
    def get_default(cls):
        return cls.__default_usbmux


Usbmux.set_default(Usbmux())


class Device(tidevice.Device):

    def __init__(self, udid: Optional[str] = None, usbmux: Union[Usbmux, str, None] = None):
        super().__init__(udid, usbmux or Usbmux.get_default())

    def relay(self, local_port: int, remote_port: int):

        class ProxyThread(threading.Thread):

            def __init__(self):
                super().__init__()
                self._loop = None
                self._event = None
                self._lock = threading.RLock()
                self._stopped = False

            def run(self):
                with self._lock:
                    if self._stopped:
                        return
                    loop = self._loop = asyncio.new_event_loop()
                    asyncio.set_event_loop(loop)
                    event = self._event = asyncio.Event()

                server = None
                try:
                    coro = asyncio.start_server(self._handle_client, '127.0.0.1', local_port)
                    server = loop.run_until_complete(coro)
                    logger.debug(f"Usbmux proxy serving on {server.sockets[0].getsockname()}")
                    loop.run_until_complete(event.wait())
                except Exception as e:
                    logger.error(f"Usbmux proxy error: {e}")
                finally:
                    if server:
                        logger.debug(f"Usbmux proxy close")
                        server.close()
                        loop.run_until_complete(server.wait_closed())
                    loop.close()

            def stop(self):
                with self._lock:
                    self._stopped = True
                    if self._loop and self._event:
                        self._loop.call_soon_threadsafe(self._event.set)

            @classmethod
            async def _handle_client(cls, client_reader: StreamReader, client_writer: StreamWriter):

                client_address = client_writer.get_extra_info('peername')
                plist_socket, usbmux_reader, usbmux_writer = None, None, None

                try:
                    logger.debug(f"Handle client proxy request: {client_address}")

                    plist_socket = self.create_inner_connection(remote_port)
                    usbmux_reader, usbmux_writer = await asyncio.open_connection(sock=plist_socket.get_socket())

                    task1 = asyncio.create_task(cls._forward_stream(usbmux_reader, client_writer))
                    task1.add_done_callback(lambda _: usbmux_writer.close())

                    task2 = asyncio.create_task(cls._forward_stream(client_reader, usbmux_writer))
                    task1.add_done_callback(lambda _: client_writer.close())

                    await asyncio.wait((task1, task2))

                except tidevice.MuxReplyError as e:
                    logger.debug(f"connect to device error: {e}")

                finally:
                    if usbmux_writer:
                        await cls._close_stream(usbmux_writer)
                    if client_writer:
                        await cls._close_stream(client_writer)
                    if plist_socket:
                        plist_socket.close()

                    logger.debug(f"handle client proxy request finished: {client_address}")

            @classmethod
            async def _forward_stream(cls, reader: StreamReader, writer: StreamWriter):
                while True:
                    try:
                        data = await reader.read(1024 * 10)
                        if not data:
                            break
                        writer.write(data)
                        await writer.drain()
                    except Exception as e:
                        logger.debug(f"forward stream error: {e}")
                        break
                await cls._close_stream(writer)

            @classmethod
            async def _close_stream(cls, writer: StreamWriter):
                writer.close()
                if hasattr(writer, "wait_closed"):
                    await writer.wait_closed()

        thread = ProxyThread()
        thread.start()
        return thread
