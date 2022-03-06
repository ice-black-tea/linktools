#!/usr/bin/env python3
# -*- coding:utf-8 -*-

# Datetime  : 2022/2/21 下午5:26
# Author    : HuJi <jihu.hj@alibaba-inc.com>
import logging

from linktools import tools, logger

logging.basicConfig(
    level=logging.INFO,
    format='%(message)s',
)

logger.info("initialize adb ...")
tools["adb"].prepare()

try:
    from .frida import FridaAndroidServer

    logger.info("initialize android frida server ...")
    FridaAndroidServer.setup(abis=["arm", "arm64"])
except ImportError:
    logger.warning("not found frida, skip initializing android frida server")
