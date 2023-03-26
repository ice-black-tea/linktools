#!/usr/bin/env python3
# -*- coding:utf-8 -*-

# Datetime  : 2022/2/21 上午11:48
# Author    : HuJi <jihu.hj@alibaba-inc.com>

import logging

from .android import AndroidFridaServer
from .. import environ

logging.basicConfig(
    level=logging.INFO,
    format="%(message)s",
)

environ.get_logger().info("initialize android frida server ...")
AndroidFridaServer.setup(abis=["arm", "arm64"])
