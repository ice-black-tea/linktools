#!/usr/bin/env python3
# -*- coding:utf-8 -*-

# Datetime  : 2022/2/21 上午11:48
# Author    : HuJi <jihu.hj@alibaba-inc.com>

import logging

from .android import AndroidFridaServer
from .. import logger

logging.basicConfig(
    level=logging.INFO,
    format="%(message)s",
)

logger.info("initialize android frida server ...")
AndroidFridaServer.setup(abis=["arm", "arm64"])
