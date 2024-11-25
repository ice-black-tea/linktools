#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
@author  : Hu Ji
@file    : scrcpy.py
@time    : 2024/11/22 12:03 
@site    : https://github.com/ice-black-tea
@software: PyCharm

              ,----------------,              ,---------,
         ,-----------------------,          ,"        ,"|
       ,"                      ,"|        ,"        ,"  |
      +-----------------------+  |      ,"        ,"    |
      |  .-----------------.  |  |     +---------+      |
      |  |                 |  |  |     | -==----'|      |
      |  | $ sudo rm -rf / |  |  |     |         |      |
      |  |                 |  |  |/----|`---=    |      |
      |  |                 |  |  |   ,/|==== ooo |      ;
      |  |                 |  |  |  // |(((( [33]|    ,"
      |  `-----------------'  |," .;'| |((((     |  ,"
      +-----------------------+  ;;  | |         |,"
         /_)______________(_/  //'   | +---------+
    ___________________________/___  `,
   /  oooooooooooooooo  .o.  oooo /,   `,"-----------
  / ==ooooooooooooooo==.o.  ooo= //   ,``--{)B     ,"
 /_==__==========__==_ooo__ooo=_/'   /___________,"
"""
import json
import random
import socket
import subprocess
from typing import List, Dict, Any, Optional

from .adb import AdbDevice
from .. import environ, utils
from ..decorator import cached_classproperty
from ..types import Stoppable

logger = environ.get_logger("android.scrcpy")


class ScrcpyServer(Stoppable):

    def __init__(self, device: AdbDevice = None, version: str = None):
        self._device = device or AdbDevice()
        self._version = version
        self._process: Optional[utils.Process] = None

    @cached_classproperty
    def _server_info(self) -> "List[Dict[str, str]]":
        server_path = environ.get_asset_path("android-tools.json")
        server_data = json.loads(utils.read_file(server_path, text=True))
        return server_data["SCRCPY_SERVER"]

    def start(self, *args: Any):

        def start():
            server_info = dict(self._server_info)
            server_version = server_info["version"] = self._version or server_info["version"]
            server_name = server_info["name"].format(**server_info)
            server_url = server_info["url"].format(**server_info)
            server_path = environ.get_data_path("android", server_name, create_parent=True)
            if not server_path.exists():
                url_file = environ.get_url_file(server_url)
                url_file.save(server_path.parent, server_path.name)

            remote_path = self._device.push_file(
                server_path,
                self._device.get_data_path("scrcpy"),
                server_name,
                skip_exist=True,
            )
            self._process = self._device.popen(
                "shell",
                utils.list2cmdline([
                    f"CLASSPATH={remote_path}", "app_process", "/", "com.genymobile.scrcpy.Server", server_version,
                    *[str(arg) for arg in args]
                ]),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )

            for out, err in self._process.fetch(timeout=1):
                if err:
                    logger.warning(err)

            return self

        return self._stop_on_error(start)

    def stop(self):
        if self._process:
            utils.ignore_error(self._process.kill)
            try:
                self._process.wait(5)
            except subprocess.TimeoutExpired:
                utils.ignore_error(self._process.terminate)
                logger.warning("Scrcpy server stop timeout")
            self._process = None


class ScrcpyConnection(Stoppable):

    def __init__(self, device: AdbDevice = None, version: str = None):
        self._device = device or AdbDevice()
        self._server = ScrcpyServer(device=self._device, version=version)
        self._scid = None
        self._forward = None
        self._socket = None

    @property
    def socket(self) -> Optional[socket.socket]:
        return self._socket

    @property
    def closed(self) -> bool:
        return self._socket is not None

    def start(self, *args: str):

        def start():
            self._scid = str(random.randint(0, 5)) + "".join([hex(random.randint(1, 15))[-1] for _ in range(7)])
            self._server.start(
                "tunnel_forward=true",
                "cleanup=false",
                f"scid={self._scid}",
                *args,
            )
            self._forward = self._device.forward("tcp:0", f"localabstract:scrcpy_{self._scid}")
            self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._socket.connect(("localhost", self._forward.local_port))
            return self

        return self._stop_on_error(start)

    def stop(self):
        self._scid = None
        if self._socket:
            logger.debug("Close scrcpy socket")
            utils.ignore_error(self._socket.close)
            self._socket = None
        if self._forward:
            self._forward.stop()
            self._forward = None
        self._server.stop()


if __name__ == '__main__':
    import logging
    import struct
    import av
    import cv2
    from .. import rich

    rich.init_logging(level=logging.DEBUG, show_level=True)

    with ScrcpyConnection().start(
            f"video=true",
            f"audio=false",
            f"control=false",
            f"max_size=1000",
            f"max_fps=30",
            f"video_codec=h264",
            f"video_source=display",
            f"log_level=warn",
            f"send_frame_meta=false"
    ) as conn:
        if conn.socket.recv(1) != b'\x00':
            raise ConnectionError('Did not receive Dummy Byte!')

        device_name = conn.socket.recv(64).decode().rstrip('\x00')
        if not len(device_name):
            raise ConnectionError("Did not receive Device Name!")
        logger.info(f"Device Name: {device_name}")

        video_codec = conn.socket.recv(4).decode()
        logger.info(f"Video codec: {video_codec}")

        (width, height,) = struct.unpack(">II", conn.socket.recv(8))
        logger.info(f"Video width: {width}, height: {height}")

        codec = av.codec.CodecContext.create("h264", "r")
        while not conn.closed:
            raw_h264 = conn.socket.recv(0x10000)
            packets = codec.parse(raw_h264)
            if not packets:
                continue

            result_frames = []

            for packet in packets:
                frames = codec.decode(packet)
                for frame in frames:
                    result_frames.append(frame.to_ndarray(format='bgr24'))

            if result_frames:
                cv2.namedWindow("game", cv2.WINDOW_NORMAL)
                for frame in result_frames:
                    cv2.imshow("game", frame)
                    cv2.waitKey(0)
                break
