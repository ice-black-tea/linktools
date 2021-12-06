#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
@author  : Hu Ji
@file    : frida.py
@time    : 2018/11/25
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
import codecs
import fnmatch
import lzma
import os
import shutil
import threading
import time
from pathlib import Path, PosixPath
from typing import Optional, Union

import _frida
import frida
from calmjs.parse import es5
from colorama import Fore
from frida_tools.application import Reactor

import linktools
from linktools import utils, resource, logger
from linktools.android import adb
from linktools.decorator import cached_property


class FridaServer(utils.Proxy):  # proxy for frida.core.Device
    __setattr__ = object.__setattr__

    def __init__(self, device: frida.core.Device):
        super().__init__(lambda: device)

    def start(self):
        pass

    def stop(self):
        pass

    def is_running(self) -> bool:
        """
        判断服务端运行状态
        :return: 是否正在运行
        """
        try:
            processes = self.enumerate_processes()
            return processes is not None
        except (frida.TransportError, frida.ServerNotRunningError):
            return False

    def get_process(self, pid: int = None, process_name: str = None) -> Optional["_frida.Process"]:
        """
        通过进程名到的所有进程
        :param pid: 进程id
        :param process_name: 进程名
        :return: 进程
        """
        if process_name is not None:
            process_name = process_name.lower()
        for process in self.enumerate_processes():
            if pid is not None:
                if process.pid == pid:
                    return process
            elif process_name is not None:
                if fnmatch.fnmatchcase(process.name.lower(), process_name):
                    return process
        raise frida.ProcessNotFoundError("unable to find process with pid '%s', name '%s'" % (pid, process_name))

    def get_processes(self, package_name: str = None) -> ["_frida.Process"]:
        """
        根据包名匹配进程名
        :param package_name: 进程名（支持正则）
        :return: 进程列表
        """
        try:
            all_processes = self.enumerate_processes()
            if package_name is None:
                return all_processes
            processes = []
            for process in all_processes:
                if self.fix_package_name(process.name) == package_name:
                    processes.append(process)
            return processes
        except Exception as e:
            logger.error(e, tag="[!]", fore=Fore.RED)
            return []

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.stop()


class FridaAndroidServer(FridaServer):

    def __init__(self, device_id: str = None, local_port=47042, remote_port=47042):
        self._device = adb.Device(device_id=device_id)
        self._local_port = local_port
        self._remote_port = remote_port
        self._local_address = f"localhost:{self._local_port}"
        super().__init__(frida.get_device_manager().add_remote_device(self._local_address))

        # frida server文件相关参数
        self._download_url = self.config["url"]
        # local: {storage_path}/data/frida/frida-server-xxx
        self._local_path = Path(resource.get_data_dir("frida", create=True)) / self.config["name"]
        # android: {storage_path}/frida/frida-server-xxx
        self._remote_temp_path = PosixPath(self._device.get_storage_path()) / "frida" / self.config["name"]
        # android: /data/local/tmp/fs-xxx
        self._remote_path = PosixPath("/data/local/tmp") / "fs-{abi}-{version}".format(**self.config)

    @cached_property
    def config(self) -> dict:
        config = linktools.config["ANDROID_TOOL_FRIDA_SERVER"].copy()
        config["version"] = frida.__version__
        config["abi"] = self._device.abi
        config["url"] = config["url"].format(**config)
        config["name"] = config["name"].format(**config)
        return config

    @staticmethod
    def _start(device: adb.Device, remote_path: str, remote_port: Union[str, int]):
        try:
            device.sudo(
                remote_path,
                "-l", f"0.0.0.0:{remote_port}",
                capture_output=False
            )
        except:
            logger.error(f"Frida server stop", tag="[!]", fore=Fore.RED)

    def start(self) -> bool:
        """
        根据frida版本和设备abi类型下载并运行server
        :return: 运行成功为True，否则为False
        """
        if self._local_port is not None:
            self._device.forward(f"tcp:{self._local_port}", f"tcp:{self._remote_port}")

        if self.is_running():
            logger.info("Frida server is running ...", tag="[*]")
            return True

        logger.info("Start frida server ...", tag="[*]")

        self._prepare()
        threading.Thread(
            target=self._device.sudo,
            args=(
                self._remote_path.as_posix(),
                "-l", f"0.0.0.0:{self._remote_port}",
            ),
            daemon=True
        ).start()

        for i in range(10):
            time.sleep(0.5)
            if self.is_running():
                logger.info("Frida server is running ...", tag="[*]")
                return True

        raise frida.ServerNotRunningError("Frida server failed to run ...")

    def _prepare(self):
        if self._device.is_file_exist(self._remote_path.as_posix()):
            return

        if not os.path.exists(self._local_path):
            logger.info("Download frida server ...", tag="[*]")
            tmp_file = resource.get_temp_path(self._local_path.name + ".tmp")
            utils.download(self._download_url, tmp_file)
            with lzma.open(tmp_file, "rb") as read, open(self._local_path, "wb") as write:
                shutil.copyfileobj(read, write)
            os.remove(tmp_file)

        logger.info("Push frida server to %s" % self._remote_path, tag="[*]")
        self._device.push(self._local_path, self._remote_temp_path.as_posix(), capture_output=False)
        self._device.sudo("mv", self._remote_temp_path.as_posix(), self._remote_path.as_posix(), capture_output=False)
        self._device.sudo("chmod 755 '%s'" % self._remote_path)

    def stop(self) -> bool:
        """
        强制结束frida server
        :return: 结束成功为True，否则为False
        """

        logger.info("Kill frida server ...", tag="[*]")
        try:
            process = self.get_process(process_name=f"*{self._remote_path.name}*")
            self.kill(process.pid)
            return True
        except frida.ServerNotRunningError:
            return True
        except:
            return False

    def is_running(self) -> bool:
        """
        判断服务端运行状态
        :return: 是否正在运行
        """
        try:
            process = self.get_process(process_name=f"*{self._remote_path.name}*")
            return process is not None
        except (frida.TransportError, frida.ServerNotRunningError, frida.ProcessNotFoundError):
            return False


class FridaSession(utils.Proxy):  # proxy for frida.core.Session
    __setattr__ = object.__setattr__

    def __init__(self, session: frida.core.Session):
        super().__init__(lambda: session)
        self.pid: Optional[int] = None
        self.process_name: Optional[str] = None
        self.script: Optional[FridaScript] = None


class FridaScript(utils.Proxy):  # proxy for frida.core.Session
    __setattr__ = object.__setattr__

    def __init__(self, script: frida.core.Script):
        super().__init__(lambda: script)
        self.session: Optional[FridaSession] = None


# noinspection PyUnresolvedReferences
class FridaApplication:
    """
    ----------------------------------------------------------------------

    eg.
        #!/usr/bin/env python3
        # -*- coding: utf-8 -*-

        from linktools.android.frida import FridaAndroidServer, FridaApplication

        jscode = \"\"\"
            var $ = new JavaHelper();
            $.hookMethods(
                "java.util.HashMap", "put", $.getHookImpl({printStack: false, printArgs: true})
            );
        \"\"\"

        if __name__ == "__main__":

            with FridaAndroidServer() as server:

                app = FridaApplication(
                    server,
                    eval_code=jscode,
                    enable_spawn_gating=True
                )

                for target_app in app.device.enumerate_applications():
                    if target_app.identifier == "com.topjohnwu.magisk":
                        app.load_script(target_app.pid)

                app.run()

    ----------------------------------------------------------------------
    """

    def __init__(
            self,
            server: FridaServer,
            user_script: str = None,
            eval_code: str = None,
            enable_spawn_gating=False,
            enable_child_gating=False,
            eternalize=False):
        """
        :param server: 环境信息
        """
        self._server = server

        self._stop_requested = threading.Event()
        self._reactor = Reactor(
            run_until_return=self._run,
            on_stop=self._on_stop
        )

        self._user_script = user_script
        self._eval_code = eval_code
        self._enable_spawn_gating = enable_spawn_gating
        self._enable_child_gating = enable_child_gating
        self._eternalize = eternalize

        self._sessions = {}
        self._last_change_id = 0
        self._monitored_files = {}

        self._init()

    def _init(self):
        self.spawn = self.device.spawn
        self.resume = self.device.resume
        self.enumerate_applications = self.device.enumerate_applications
        self.enumerate_processes = self.device.enumerate_processes
        self.get_frontmost_application = self.device.get_frontmost_application

        self.device.on("spawn-added", lambda spawn: threading.Thread(target=self.on_spawn_added, args=(spawn,)).start())
        self.device.on("spawn-removed", lambda spawn: self._reactor.schedule(self.on_spawn_removed))
        self.device.on("child-added", lambda child: self._reactor.schedule(self.on_child_added(child)))
        self.device.on("child-removed", lambda child: self._reactor.schedule(self.on_child_removed(child)))
        self.device.on("output", lambda pid, fd, data: self._reactor.schedule(self.on_output(pid, fd, data)))
        # self.device.on('process-crashed', xxx)
        # self.device.on('output', xxx)
        # self.device.on('uninjected', xxx)
        # self.device.on('lost', xxx)

        if self._enable_spawn_gating:
            self.device.enable_spawn_gating()

    @property
    def device(self) -> frida.core.Device:
        # noinspection PyTypeChecker
        return self._server

    @cached_property
    def _persist_codes(self):
        with open(resource.get_persist_path("android-frida.js"), "rt") as fd:
            return [es5.minify_print(fd.read())]

    def run(self):
        try:
            self._monitor_all()
            self._reactor.run()
        finally:
            self._demonitor_all()
            self._reactor.stop()

    def _run(self, reactor):
        try:
            self._stop_requested.wait()
        except:
            self._stop_requested.set()

    def is_running(self):
        return not self._stop_requested.wait(0)

    def stop(self):
        self._stop_requested.set()

    def load_script(self, pid, resume=False):
        """
        加载脚本，注入到指定进程
        :param pid: 进程id
        :param resume: 注入后是否需要resume进程
        """
        self._reactor.schedule(lambda: self._load_script(pid, resume))

    def attach_session(self, pid):
        """
        附加指定进程
        :param pid: 进程id
        """
        self._reactor.schedule(lambda: self._attach_session(pid))

    def detach_session(self, pid):
        """
        分离指定进程
        :param pid: 进程id
        """
        self._reactor.schedule(lambda: self._detach_session(pid))

    def _load_script(self, pid: int, resume: bool = False):
        logger.debug(f"Attempt to load script: pid={pid}, resume={resume}", tag="[✔]")

        codes = [*self._persist_codes]
        if self._user_script is not None:
            with codecs.open(self._user_script, 'rb', 'utf-8') as f:
                codes.append(f.read())
        if self._eval_code is not None:
            codes.append(self._eval_code)

        try:
            session = self._attach_session(pid)

            script = FridaScript(session.create_script(";".join(codes)))
            script.session = session

            script.on("message", lambda message, data: self.on_script_message(script, message))
            script.on("destroyed", lambda: self.on_script_destroyed(script))

            self._unload_script(pid)
            script.load()
            session.script = script

            if resume:
                self.device.resume(pid)

            self._reactor.schedule(lambda: self.on_script_loaded(script))

        except Exception as e:
            logger.info(f"Load script error: {e}", tag="[!]", fore=Fore.RED)
            raise e

    def _attach_session(self, pid: int):
        try:
            session = self._sessions.get(pid)
            if session is not None:
                return session

            logger.debug(f"Attempt to attach process: pid={pid}", tag="[✔]")

            process = self.device.get_process(pid=pid)
            session = FridaSession(self.device.attach(process.pid))
            session.pid = process.pid
            session.process_name = process.name

            if self._enable_child_gating:
                logger.debug(f"Enable chile gating: {pid}", tag="[✔]")
                session.enable_child_gating()

            def on_session_detached(reason):
                if pid in self._sessions:
                    del self._sessions[pid]
                # self.on_session_detached(session, reason)
                self._reactor.schedule(lambda: self.on_session_detached(session, reason))

            session.on("detached", on_session_detached)
            self._sessions[process.pid] = session
            self._reactor.schedule(lambda: self.on_session_attached(session))

            return session

        except Exception as e:
            logger.info(f"Attach session error: {e}", tag="[!]", fore=Fore.RED)
            raise e

    def _detach_session(self, pid: int):
        session = self._sessions.get(pid)
        if session is not None:
            logger.debug(f"Detach process: pid={pid}", tag="[✔]")
            try:
                session.detach()
            except:
                pass

    def _unload_script(self, pid: int):
        session = self._sessions.get(pid)
        if session is not None and session.script is not None:
            logger.debug(f"Unload script: pid={pid}", tag="[✔]")
            try:
                session.script.unload()
            except:
                pass
            session.script = None

    def _eternalize_script(self, pid: int):
        session = self._sessions.get(pid)
        if session is not None and session.script is not None:
            logger.debug(f"Eternalize script: pid={pid}", tag="[✔]")
            try:
                session.script.eternalize()
            except:
                pass
            session.script = None

    def _monitor_all(self):

        def on_change(changed_file, other_file, event_type):
            if event_type == 'changes-done-hint':
                return
            self._last_change_id += 1
            change_id = self._last_change_id
            self._reactor.schedule(lambda: process_change(change_id, changed_file), delay=0.05)

        def process_change(change_id, changed_file):
            if change_id != self._last_change_id:
                return
            try:
                self.on_file_change(changed_file)
            except Exception as e:
                logger.info(f"Failed to load script: {e}", tag="[!]", fore=Fore.RED)

        for path in [self._user_script]:
            if path is None or path in self._monitored_files:
                return

            logger.debug(f"Monitor file: {path}", tag="[✔]")
            monitor = frida.FileMonitor(path)
            monitor.on('change', on_change)
            monitor.enable()
            self._monitored_files[path] = monitor

    def _demonitor_all(self):
        for monitor in self._monitored_files.values():
            monitor.disable()
        self._monitored_files = {}

    def _on_stop(self):
        logger.debug("Stop frida application", tag="[✔]")
        process_script = self._unload_script
        if self._eternalize:
            process_script = self._eternalize_script
        for session in [s for s in self._sessions.values()]:
            process_script(session.pid)
            self._detach_session(session.pid)

        with frida.Cancellable():
            self._demonitor_all()

    def on_output(self, pid: int, fd, data):
        logger.debug(f"Output: pid={pid}, fd={fd}, data={data}", tag="[✔]")

    def on_file_change(self, file: str):
        """
        脚本文件改变回调，默认重新加载脚本
        :param file: 脚本文件路径
        """
        logger.debug(f"File changed: {file}", tag="[✔]")
        for session in self._sessions.values():
            self._load_script(session.pid)

    def on_spawn_added(self, spawn: "_frida.Spawn"):
        """
        spaw进程添加回调，默认resume所有spawn进程
        :param spawn: spawn进程信息
        """
        logger.debug(f"Spawn added: {spawn}", tag="[✔]")
        self.device.resume(spawn.pid)

    def on_spawn_removed(self, spawn: "_frida.Spawn"):
        """
        spaw进程移除回调，默认只打印log
        :param spawn: spawn进程信息
        """
        logger.debug(f"Spawn removed: {spawn}", tag="[✔]")

    def on_child_added(self, child: "_frida.Child"):
        """
        子进程添加回调，默认resume所有子进程
        :param child: 子进程信息
        """
        logger.debug(f"Child added: {child}", tag="[✔]")
        self.device.resume(child.pid)

    def on_child_removed(self, child: "_frida.Child"):
        """
        子进程移除回调，默认只打印log
        :param child: 子进程信息
        """
        logger.debug(f"Child removed: {child}", tag="[✔]")

    def on_script_loaded(self, script: FridaScript):
        """
        脚本加载回调，默认只打印log
        :param script: frida的脚本
        """
        logger.debug(f"Script loaded: {script.session.process_name} ({script.session.pid})", tag="[✔]")

    def on_script_destroyed(self, script: FridaScript):
        """
        脚本结束回调函数，默认只打印log
        :param script: frida的脚本
        """
        logger.debug(f"Script destroyed: {script.session.process_name} ({script.session.pid})", tag="[✔]")

    def on_script_message(self, script: FridaScript, message: object):
        """
        脚本消息回调函数，默认按照格式打印
        :param script: frida的脚本
        :param message: frida server发送的数据
        """
        if utils.get_item(message, "type") == "send":
            payload = utils.get_item(message, "payload")

            stack = utils.pop_item(payload, "stack")
            if not utils.is_empty(stack):
                logger.info(stack, tag=f"[*]", fore=Fore.CYAN)

            arguments = utils.pop_item(payload, "arguments")
            if not utils.is_empty(arguments):
                logger.info(arguments, tag="[*]", fore=Fore.LIGHTMAGENTA_EX)

            if not utils.is_empty(payload):
                logger.info(payload, tag="[*]")

        elif utils.get_item(message, "type") == "error" and utils.is_contain(message, "stack"):
            logger.info(utils.get_item(message, "stack"), tag="[*]", fore=Fore.RED)

        else:
            logger.info(message, tag="[?]", fore=Fore.RED)

    def on_session_attached(self, session: FridaSession):
        """
        会话建立连接回调函数，默认只打印log
        :param session: 附加的会话
        """
        logger.info(f"Session attached: {session.process_name} ({session.pid})", tag="[*]")

    def on_session_detached(self, session: FridaSession, reason: str):
        """
        会话结束回调函数，默认处理当session全部失效时结束
        :param session: 结束的会话
        :param reason: 结束原因
        """
        logger.info(f"Session detached: {session.process_name} ({session.pid}), reason={reason}", tag="[*]")
        if len(self._sessions) == 0:
            self.stop()
