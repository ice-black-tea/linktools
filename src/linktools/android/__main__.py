#!/usr/bin/env python3
# -*- coding:utf-8 -*-

# Datetime  : 2022/2/21 下午5:26
# Author    : HuJi <jihu.hj@alibaba-inc.com>

import logging

from .. import tools, logger

logging.basicConfig(
    level=logging.INFO,
    format='%(message)s',
)

logger.info("initialize adb ...")
tools["adb"].prepare()
