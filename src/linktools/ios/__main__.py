#!/usr/bin/env python3
# -*- coding:utf-8 -*-

# Datetime  : 2022/2/21 下午5:36
# Author    : HuJi <jihu.hj@alibaba-inc.com>

import logging

from .. import environ

logging.basicConfig(
    level=logging.INFO,
    format='%(message)s',
)

environ.get_logger().info("initialize sib ...")
environ.get_tool("sib").prepare()
