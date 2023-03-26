#!/usr/bin/env python3
# -*- coding:utf-8 -*-

# Datetime  : 2022/2/21 下午5:26
# Author    : HuJi <jihu.hj@alibaba-inc.com>

import logging

from .. import environ

logging.basicConfig(
    level=logging.INFO,
    format='%(message)s',
)

environ.get_logger().info("initialize adb ...")
environ.get_tool("adb").prepare()
