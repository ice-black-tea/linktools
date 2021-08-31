#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
@author  : Hu Ji
@file    : tools.py 
@time    : 2021/08/06
@site    :  
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
   /  oooooooooooooooo  .o.  oooo /,   \,"-----------
  / ==ooooooooooooooo==.o.  ooo= //   ,`\--{)B     ,"
 /_==__==========__==_ooo__ooo=_/'   /___________,"
"""

GENERAL_TOOL_BAKSMALI = {
    "version": "2.5.2",
    "download_url": "https://bitbucket.org/JesusFreke/smali/downloads/baksmali-{version}.jar",
    "relative_path": "baksmali-{version}.jar",
    "executable": ["java", "-jar", "{absolute_path}"]
}

GENERAL_TOOL_SMALI = {
    "version": "2.5.2",
    "download_url": "https://bitbucket.org/JesusFreke/smali/downloads/smali-{version}.jar",
    "relative_path": "smali-{version}.jar",
    "executable": ["java", "-jar", "{absolute_path}"]
}

GENERAL_TOOL_APKTOOL = {
    "version": "2.5.0",
    "download_url": "https://bitbucket.org/iBotPeaches/apktool/downloads/apktool_{version}.jar",
    "relative_path": "apktool-{version}.jar",
    "executable": ["java", "-jar", "{absolute_path}"]
}

GENERAL_TOOL_DEX2JAR = {
    "version": "2.1",
    "download_url": "https://github.com/pxb1988/dex2jar/files/1867564/dex-tools-2.1-SNAPSHOT.zip",
    "unpack_path": "dex2jar-{version}",
    "relative_path": {
        "darwin": "dex-tools-{version}-SNAPSHOT/d2j-dex2jar.sh",
        "linux": "dex-tools-{version}-SNAPSHOT/d2j-dex2jar.sh",
        "windows": "dex-tools-{version}-SNAPSHOT/d2j-dex2jar.bat"
    }
}

GENERAL_TOOL_ADB = {
    "command": "adb",
    "download_url": "https://dl.google.com/android/repository/platform-tools-latest-{system}.zip",
    "unpack_path": "platform-tools",
    "relative_path": {
        "darwin": "platform-tools/adb",
        "linux": "platform-tools/adb",
        "windows": "platform-tools/adb.exe"
    }
}

GENERAL_TOOL_FASTBOOT = {
    "parent": GENERAL_TOOL_ADB,
    "command": "fastboot",
    "relative_path": {
        "darwin": "platform-tools/fastboot",
        "linux": "platform-tools/fastboot",
        "windows": "platform-tools/fastboot.exe"
    }
}

GENERAL_TOOL_JAVA = {
    "command": "java",
    "version": "1.8.0_121",
    "unpack_path": "java-{version}",
    "darwin": {
        "download_url": "https://bitbucket.org/ice-black-tea/jre/downloads/jre-8u121-macosx-x64.tar.gz",
        "relative_path": "jre{version}.jre/Contents/Home/bin/java",
    },
    "linux": {
        "download_url": "https://bitbucket.org/ice-black-tea/jre/downloads/jre-8u121-linux-x64.tar.gz",
        "relative_path": "jre{version}/bin/java",
    },
    "windows": {
        "download_url": "https://bitbucket.org/ice-black-tea/jre/downloads/jre-8u121-windows-x64.tar.gz",
        "relative_path": "jre{version}/bin/java.exe",
    }
}

GENERAL_TOOL_MIPAY_EXTRACT = {
    "version": "8.12.6",
    "download_url": "https://bitbucket.org/ice-black-tea/tools/downloads/mipay-extract-{version}.zip",
    "unpack_path": "eufix-{version}",
    "relative_path": {
        "darwin": "extract.sh",
        "linux": "extract.sh",
        "windows": "extract.bat"
    }
}

GENERAL_TOOL_VDEX_EXTRACTOR = {
    "parent": GENERAL_TOOL_MIPAY_EXTRACT,
    "relative_path": {
        "darwin": "tools/darwin/vdexExtractor",
        "linux": "tools/vdexExtractor",
        "windows": "tools/vdexExtractor"
    }
}

GENERAL_TOOL_COMPACT_DEX_CONVERTER = {
    "parent": GENERAL_TOOL_MIPAY_EXTRACT,
    "relative_path": {
        "darwin": "tools/cdex/compact_dex_converter_mac",
        "linux": "tools/cdex/compact_dex_converter_linux",
        "windows": "tools/cdex/flinux.exe"
    },
    "windows": {
        "executable": [
            "tools/cdex/flinux.exe",
            "tools/cdex/compact_dex_converter_linux"
        ]
    }
}

GENERAL_TOOL_AAPT = {
    "command": "aapt",
    "version": "v0.2-4913185",
    "unpack_path": "aapt-{version}",
    "darwin": {
        "download_url": "https://dl.androidaapt.com/aapt-macos.zip",
        "relative_path": "aapt"
    },
    "linux": {
        "download_url": "https://dl.androidaapt.com/aapt-linux.zip",
        "relative_path": "aapt"
    },
    "windows": {
        "download_url": "https://dl.androidaapt.com/aapt-windows.zip",
        "relative_path": "aapt.exe"
    }
}

GENERAL_TOOL_JADX = {
    "version": "1.2.0",
    "download_url": "https://github.com/skylot/jadx/releases/download/v{version}/jadx-{version}.zip",
    "unpack_path": "jadx-{version}",
    "relative_path": {
        "darwin": "bin/jadx",
        "linux": "bin/jadx",
        "windows": "bin/jadx.bat"
    }
}

GENERAL_TOOL_JADX_GUI = {
    "parent": GENERAL_TOOL_JADX,
    "name": "jadx-gui",
    "relative_path": {
        "darwin": "bin/jadx-gui",
        "linux": "bin/jadx-gui",
        "windows": "bin/jadx-gui.bat"
    }
}

GENERAL_TOOL_CHROMEDRIVER = {
    "command": "chromedriver",
    "version": "87.0.4280.88",
    "unpack_path": "chromedriver-{version}",
    "darwin": {
        "download_url": "http://chromedriver.storage.googleapis.com/{version}/chromedriver_mac64.zip",
        "relative_path": "chromedriver"
    },
    "linux": {
        "download_url": "http://chromedriver.storage.googleapis.com/{version}/chromedriver_linux64.zip",
        "relative_path": "chromedriver"
    },
    "windows": {
        "download_url": "http://chromedriver.storage.googleapis.com/{version}/chromedriver_win32.zip",
        "relative_path": "chromedriver.exe"
    }
}
