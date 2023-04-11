#!/usr/bin/env python3
# -*- coding:utf-8 -*-

# Author    : HuJi <jihu.hj@alibaba-inc.com>
# Datetime  : 2022/1/13 下午8:53
# User      : huji
# Product   : PyCharm
# Project   : link

import os
import plistlib
import re
import zipfile
from typing import Optional


class IPAError(Exception):
    pass


class IPA(object):
    _INFO_PLIST = "Info.plist"

    def __init__(self, filename: str):
        self.filename = filename
        self.zip = zipfile.ZipFile(self.filename)
        self._plist = {}
        self._analysis()

    def _analysis(self):
        plist_path = self.find_file(self._INFO_PLIST)
        if plist_path is None:
            raise IPAError("missing Info.plist")
        plist_data = self.zip.read(plist_path)
        self._plist[self._INFO_PLIST] = plistlib.loads(plist_data)

    def find_file(self, name) -> Optional[str]:
        name_list = self.zip.namelist()
        pattern = re.compile(rf'Payload/[^/]+\.app/{name}$')
        for path in name_list:
            m = pattern.match(path)
            if m is not None:
                return m.group()
        return None

    def get_files(self):
        return self.zip.namelist()

    def get_file(self, filename):
        try:
            return self.zip.read(filename)
        except KeyError:
            raise IPAError(f"file not found: {filename}")

    def get_info_plist(self):
        return self._plist[self._INFO_PLIST]

    def get_launch_storyboard_name(self):
        return self.get_info_plist().get("UILaunchStoryboardName")

    def get_display_name(self):
        return self.get_info_plist().get("CFBundleDisplayName")

    def get_bundle_id(self):
        return self.get_info_plist().get("CFBundleIdentifier")

    def get_version(self):
        return self.get_info_plist().get("CFBundleVersion")

    def get_version_string(self):
        return self.get_info_plist().get("CFBundleShortVersionString")

    def get_permssions(self):
        plist = self.get_info_plist()
        for key in plist:
            if key.endswith("Description"):
                print(key, plist[key])


if __name__ == '__main__':
    IPA(os.path.expanduser("~/Downloads/201200@蜂鸟跑腿.ipa")).get_permssions()
