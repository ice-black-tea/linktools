#!/usr/bin/env python3
# -*- coding:utf-8 -*-

# Author    : HuJi <jihu.hj@alibaba-inc.com>
# Datetime  : 2022/3/3 3:26 PM
# User      : huji
# Product   : PyCharm
# Project   : link

__all__ = ("get_chrome_driver",)

import json

from . import utils
from .environ import tools, resource


class NotFoundVersion(Exception):
    pass


def _split_version(version):
    return tuple(int(i) for i in version.split("."))


def get_chrome_driver(version: str):
    chrome_driver = tools["chromedriver80"]
    base_url = chrome_driver.config.get("base_url")

    versions = _split_version(version)
    if versions[0] >= 70:
        path = resource.get_temp_path("webdriver", f"chromedriver-{versions[0]}.xml", create_parent=True)
        utils.download(f"{base_url}/LATEST_RELEASE_{versions[0]}", path)
        with open(path, "rt") as fd:
            return chrome_driver.copy(version=fd.read())

    path = resource.get_path("chrome-driver.json")
    with open(path, "rt") as fd:
        version_map = json.load(fd)

    for key, value in version_map.items():
        if versions[0] == _split_version(value)[0]:
            return chrome_driver.copy(version=key)

    raise NotFoundVersion(version)
