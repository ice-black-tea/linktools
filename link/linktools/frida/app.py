#!/usr/bin/env python3
# -*- coding:utf-8 -*-

# Author    : HuJi <jihu.hj@alibaba-inc.com>
# Datetime  : 2021/12/20 3:41 下午
# User      : huji
# Product   : PyCharm
# Project   : link

__all__ = ("FridaApplication",)

import json
import logging
import os
import threading
from typing import Optional, Union, Dict, Collection, Callable

import _frida
import frida
from colorama import Fore

from linktools import utils, resource, logger
from linktools.frida.script import FridaScriptFile, FridaEvalCode, FridaShareScript


class FridaReactor(utils.Reactor):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.io_cancellable = frida.Cancellable()
        # self.ui_cancellable = frida.Cancellable()
        # self._ui_cancellable_fd = self.ui_cancellable.get_pollfd()

    def cancel_io(self):
        self.io_cancellable.cancel()

    # def _run(self):
    #     super()._run()
    #     self.ui_cancellable.cancel()

    # def __del__(self):
    #     self._ui_cancellable_fd.release()

    def _work(self, fn):
        with self.io_cancellable:
            try:
                fn()
            except frida.OperationCancelledError:
                pass


class FridaSession(utils.Proxy):  # proxy for frida.core.Session
    __setattr__ = object.__setattr__

    def __init__(self, session: frida.core.Session):
        super().__init__(lambda: session)
        self.pid: Optional[int] = None
        self.process_name: Optional[str] = None
        self.script: Optional[FridaScript] = None


class FridaScript(utils.Proxy):  # proxy for frida.core.Session
    __setattr__ = object.__setattr__

    def __init__(self, session: FridaSession, code: str):
        super().__init__(lambda: session.create_script(code))
        self.session: FridaSession = session

    @property
    def pid(self) -> int:
        return self.session.pid

    @property
    def process_name(self) -> str:
        return self.session.process_name


# noinspection PyUnresolvedReferences
class FridaApplication:
    """
    ----------------------------------------------------------------------

    eg.
        #!/usr/bin/env python3
        # -*- coding: utf-8 -*-

        from linktools.android.frida import FridaAndroidServer, FridaApplication

        jscode = \"\"\"
            Java.perform(function () {
                JavaHelper.hookMethods(
                    "java.util.HashMap", "put", JavaHelper.getHookImpl({
                        printStack: false,
                        printArgs: true,
                    })
                );
            });
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
            device: Union[frida.core.Device, "FridaServer"],
            user_parameters: Dict[str, any] = None,
            user_scripts: Collection[Union[str, FridaScriptFile]] = None,
            eval_code: Union[str, FridaEvalCode] = None,
            share_script: Union[str, FridaShareScript] = None,
            enable_spawn_gating: bool = False,
            enable_child_gating: bool = False,
            eternalize: str = False,
            debug: str = False,
    ):
        self.device: frida.core.Device = device
        self.spawn = self.device.spawn
        self.resume = self.device.resume
        self.enumerate_applications = self.device.enumerate_applications
        self.enumerate_processes = self.device.enumerate_processes
        self.get_frontmost_application = self.device.get_frontmost_application

        self._cb_spawn_added = lambda spawn: threading.Thread(target=self.on_spawn_added, args=(spawn,)).start()
        self._cb_spawn_removed = lambda spawn: self._reactor.schedule(self.on_spawn_removed)
        self._cb_child_added = lambda child: self._reactor.schedule(lambda: self.on_child_added(child))
        self._cb_child_removed = lambda child: self._reactor.schedule(lambda: self.on_child_removed(child))
        self._cb_output = lambda pid, fd, data: self._reactor.schedule(lambda: self.on_output(pid, fd, data))
        self._cb_lost = lambda: self._reactor.schedule(lambda: self.on_device_lost())

        self._debug = debug
        self._last_error = None
        self._stop_request = threading.Event()
        self._finished = threading.Event()
        self._reactor = FridaReactor(
            on_stop=self._on_stop,
            on_error=self._on_error
        )

        self._lock = threading.RLock()
        self._sessions: Dict[int, FridaSession] = {}
        self._last_change_id = 0
        self._monitored_files: Dict[str, frida.FileMonitor] = {}

        self._internal_script = FridaScriptFile(resource.get_path("frida.min.js"))
        self._internal_debug_script = FridaScriptFile(resource.get_path("frida.js"))

        self._user_parameters = user_parameters or {}
        self._user_scripts = [FridaScriptFile(o) if isinstance(o, str) else o for o in (user_scripts or tuple())]
        self._eval_code = FridaEvalCode(eval_code) if isinstance(eval_code, str) else eval_code
        self._share_script = FridaShareScript(share_script) if isinstance(share_script, str) else share_script

        self._enable_spawn_gating = enable_spawn_gating
        self._enable_child_gating = enable_child_gating
        self._eternalize = eternalize

    def _init(self):
        logger.debug(f"FridaApplication init", tag="[✔]")

        self._finished.clear()
        self._monitor_all()

        self.device.on("spawn-added", self._cb_spawn_added)
        self.device.on("spawn-removed", self._cb_spawn_removed)
        self.device.on("child-added", self._cb_child_added)
        self.device.on("child-removed", self._cb_child_removed)
        self.device.on("output", self._cb_output)
        # self.device.on('process-crashed', self._cb_process_crashed)
        # self.device.on('uninjected', self._cb_uninjected)
        self.device.on("lost", self._cb_lost)

        if self._enable_spawn_gating:
            self.device.enable_spawn_gating()

    def _deinit(self):
        logger.debug(f"FridaApplication deinit", tag="[✔]")

        utils.ignore_error(self.device.off, "spawn-added", self._cb_spawn_added)
        utils.ignore_error(self.device.off, "spawn-removed", self._cb_spawn_removed)
        utils.ignore_error(self.device.off, "child-added", self._cb_child_added)
        utils.ignore_error(self.device.off, "child-removed", self._cb_child_removed)
        utils.ignore_error(self.device.off, "output", self._cb_output)
        # utils.ignore_error(self.device.off, "process-crashed", self._cb_process_crashed)
        # utils.ignore_error(self.device.off, "uninjected", self._cb_uninjected)
        utils.ignore_error(self.device.off, "lost", self._cb_lost)

        with frida.Cancellable():
            self._demonitor_all()

        self._finished.set()

    @property
    def is_running(self) -> bool:
        return self._reactor.is_running()

    def run(self, timeout=None):
        assert not self.is_running
        try:
            self._init()
            with self._reactor:
                self._stop_request.wait(timeout)
        finally:
            self._deinit()

    def wait(self, timeout=None) -> bool:
        return self._finished.wait(timeout)

    def stop(self):
        self._stop_request.set()

    def run_in_block(self) -> "FridaApplication":
        assert not self.is_running
        return self

    def __enter__(self):
        self._init()
        self._reactor.run()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self._reactor.stop()
        self._reactor.wait()
        self._deinit()

    @property
    def sessions(self) -> Dict[int, FridaSession]:
        with self._lock:
            return {k: v for k, v in self._sessions.items() if not v.is_detached}

    @property
    def scripts(self) -> Dict[int, FridaScript]:
        with self._lock:
            return {k: v.script for k, v in self._sessions.items() if not v.is_detached}

    def schedule(self, fn: Callable[[], any], delay: float = None):
        self._reactor.schedule(fn, delay)

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
        session = self.sessions.get(pid)
        if session is not None:
            self._reactor.schedule(lambda: self._detach_session(session))

    def _load_script_files(self):

        script_files = []

        # 保持脚本log输出级别同步
        if logger.isEnabledFor(logging.DEBUG):
            script_files.append(FridaEvalCode("Log.setLevel(Log.debug);"))
        elif logger.isEnabledFor(logging.INFO):
            script_files.append(FridaEvalCode("Log.setLevel(Log.info);"))
        elif logger.isEnabledFor(logging.WARNING):
            script_files.append(FridaEvalCode("Log.setLevel(Log.warning);"))
        elif logger.isEnabledFor(logging.ERROR):
            script_files.append(FridaEvalCode("Log.setLevel(Log.error);"))

        if self._share_script is not None:
            script_files.append(self._share_script)

        for user_script in self._user_scripts:
            script_files.append(user_script)

        if self._eval_code is not None:
            script_files.append(self._eval_code)

        return [{"filename": o.path, "source": o.source} for o in script_files]

    def _load_script(self, pid: int, resume: bool = False):
        logger.debug(f"Attempt to load script: pid={pid}, resume={resume}", tag="[✔]")

        session = self._attach_session(pid)
        self._unload_script(session)

        # read the internal script as an entrance
        entry_code = self._internal_debug_script.source \
            if self._debug \
            else self._internal_script.source
        script = FridaScript(session, entry_code)

        script.on("message", lambda message, data: self.on_script_message(script, message, data))
        script.on("destroyed", lambda: self.on_script_destroyed(script))

        session.script = script

        try:
            script.load()
            script.exports.load_scripts(self._load_script_files(), self._user_parameters)
        finally:
            if resume:
                self.device.resume(pid)

        self._reactor.schedule(lambda: self.on_script_loaded(script))

    def _attach_session(self, pid: int):
        with self._lock:
            session = self._sessions.get(pid)
            if session is not None:
                if not session.is_detached:
                    return session
                self._sessions.pop(pid)

        logger.debug(f"Attempt to attach process: pid={pid}", tag="[✔]")

        target_process = None
        for process in self.enumerate_processes():
            if process.pid == pid:
                target_process = process
        if target_process is None:
            raise frida.ProcessNotFoundError(f"unable to find process with pid '{pid}'")

        session = FridaSession(self.device.attach(target_process.pid))
        session.pid = target_process.pid
        session.process_name = target_process.name

        if self._enable_child_gating:
            logger.debug(f"Enable child gating: {pid}", tag="[✔]")
            session.enable_child_gating()

        def on_session_detached(reason, crash):
            with self._lock:
                self._sessions.pop(pid, None)
            self._reactor.schedule(lambda: self.on_session_detached(session, reason, crash))

        session.on("detached", on_session_detached)
        with self._lock:
            self._sessions[target_process.pid] = session
        self._reactor.schedule(lambda: self.on_session_attached(session))

        return session

    def _detach_session(self, session: FridaSession):
        if session is not None:
            logger.debug(f"Detach process: pid={session.pid}", tag="[✔]")
            utils.ignore_error(session.detach)

    def _unload_script(self, session: FridaSession):
        if session is not None and session.script is not None:
            logger.debug(f"Unload script: pid={session.pid}", tag="[✔]")
            utils.ignore_error(session.script.unload)
            session.script = None

    def _eternalize_script(self, session: FridaSession):
        if session is not None and session.script is not None:
            logger.debug(f"Eternalize script: pid={session.pid}", tag="[✔]")
            utils.ignore_error(session.script.eternalize)
            session.script = None

    def _monitor_all(self):

        def monitor_file(file):
            logger.debug(f"Monitor file: {file.path}", tag="[✔]")
            monitor = frida.FileMonitor(file.path)
            monitor.on("change", lambda changed_file, other_file, event_type: on_change(event_type, file))
            monitor.enable()
            return monitor

        def on_change(event_type, changed_file):
            if event_type == "changes-done-hint":
                logger.debug(f"Monitor event: {event_type}, file: {changed_file}", tag="[✔]")
                self._last_change_id += 1
                change_id = self._last_change_id
                changed_file.clear()
                self._reactor.schedule(lambda: on_change_schedule(change_id, changed_file), delay=0.5)

        def on_change_schedule(change_id, changed_file):
            if change_id == self._last_change_id:
                self.on_file_change(changed_file)

        script_files = [*self._user_scripts]
        if self._debug:
            script_files.append(self._internal_debug_script)

        for script_file in script_files:
            if script_file.path not in self._monitored_files:
                self._monitored_files[script_file.path] = monitor_file(script_file)

    def _demonitor_all(self):
        for monitor in self._monitored_files.values():
            monitor.disable()
        self._monitored_files = {}

    def _on_stop(self):
        process_script = self._unload_script
        if self._eternalize:
            process_script = self._eternalize_script

        for session in self.sessions.values():
            process_script(session)
            self._detach_session(session)

        self.on_stop()

    def on_stop(self):
        logger.debug("Application stopped", tag="[✔]")

    def _on_error(self, exc, traceback):
        self._last_error = exc
        self.on_error(exc, traceback)

    def on_error(self, exc, traceback):
        logger.error(f"Unhandled exception: {exc.__class__.__name__}{os.linesep}{traceback}", tag="[!]", fore=Fore.RED)
        if isinstance(exc, (KeyboardInterrupt, frida.TransportError, frida.ServerNotRunningError)):
            self.stop()

    def raise_on_error(self):
        if self._last_error is not None:
            raise self._last_error

    def on_output(self, pid: int, fd, data):
        logger.debug(f"Output: pid={pid}, fd={fd}, data={data}", tag="[✔]")

    def on_device_lost(self):
        logger.info("Device lost", tag="[!]")
        self.stop()

    def on_file_change(self, file: FridaScriptFile):
        """
        脚本文件改变回调，默认重新加载脚本
        :param file: 脚本文件路径
        """
        logger.debug(f"File changed", tag="[✔]")
        for session in self.sessions.values():
            self.load_script(session.pid)

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

    def on_script_log(self, script: FridaScript, log: dict):
        """
        脚本打印日志回调
        :param script: frida的脚本
        :param log: 日志内容
        """
        level = log.get("level") or "debug"
        tag = log.get("tag") or "[*]"
        message = log.get("message")

        log_fn = logger.debug
        if level == "info":
            log_fn = logger.info
        if level == "warning":
            log_fn = logger.warning
        if level == "error":
            log_fn = logger.error

        if message is not None and isinstance(message, dict):
            stack = utils.pop_item(message, "stack")
            if not utils.is_empty(stack):
                log_fn(stack, tag=tag, fore=Fore.CYAN)

            arguments = utils.pop_item(message, "arguments")
            if not utils.is_empty(arguments):
                log_fn(arguments, tag=tag, fore=Fore.LIGHTMAGENTA_EX)

        if not utils.is_empty(message):
            log_fn(message, tag=tag)

    def on_script_event(self, script: FridaScript, message: object, data: object):
        """
        脚本发送事件回调
        :param script: frida的脚本
        :param message: 事件消息
        :param data: 事件数据
        """
        logger.info(f"Script event: {json.dumps(message, indent=2, ensure_ascii=False)}", tag="[*]")

    def on_script_send(self, script: FridaScript, type: str, message: object, data: object):
        """
        脚本调用send是收到的回调，例send({trace: "xxx"}, null)
        :param script: frida的脚本
        :param type: 上述例子的"trace"
        :param message: json/字符串消息，上述例子的"xxx"
        :param data: 上述例子的null
        """
        logger.debug(f"Script send, type={type}, message={message}", tag="[*]")

    def on_script_message(self, script: FridaScript, message: object, data: object):
        """
        脚本消息回调函数，默认按照格式打印
        :param script: frida的脚本
        :param message: frida server发送的数据
        :param data: frida server发送的data
        """
        if utils.get_item(message, "type") == "send":

            payload = utils.get_item(message, "payload")
            if payload is not None and isinstance(payload, dict):

                # log单独解析
                log = payload.pop("log", None)
                if log is not None:
                    self.on_script_log(script, log)

                # event单独解析
                event = payload.pop("event", None)
                if event is not None:
                    self.on_script_event(script, event, data)

                # 解析完log，解析其他的
                while len(payload) > 0:
                    key, value = payload.popitem()
                    self.on_script_send(script, key, value, data)

            # 字符串类型，直接输出
            if not utils.is_empty(payload):
                logger.info(payload, tag="[*]")

        elif utils.get_item(message, "type") == "error" and utils.is_contain(message, "stack"):
            logger.info(utils.get_item(message, "stack"), tag="[!]", fore=Fore.RED)

        else:
            logger.info(message, tag="[?]", fore=Fore.RED)

    def on_session_attached(self, session: FridaSession):
        """
        会话建立连接回调函数，默认只打印log
        :param session: 附加的会话
        """
        logger.info(f"Session attached: {session.process_name} ({session.pid})", tag="[*]")

    def on_session_detached(self, session: FridaSession, reason: str, crash: "_frida.Crash"):
        """
        会话结束回调函数，默认只打印log
        :param session: 结束的会话
        :param reason: 结束原因
        :param crash: crash信息
        """
        logger.info(f"Session detached: {session.process_name} ({session.pid}), reason={reason}", tag="[*]")
