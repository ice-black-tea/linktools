#!/usr/bin/env python3
# -*- coding:utf-8 -*-
# Author    : HuJi <jihu.hj@alibaba-inc.com>
# Datetime  : 2021/12/20 3:41 下午
# User      : huji
# Product   : PyCharm
# Project   : link

import abc
import json
import logging
import os
import threading
from typing import Optional, Union, Dict, Collection, Callable, Any

import _frida
import frida
from frida.core import Session, Script

from .script import FridaUserScript, FridaEvalCode, FridaScriptFile
from .server import FridaServer
from ._utils import Counter
from .. import utils, resource, get_logger, environ

_logger = get_logger("frida.app")


class FridaSession(utils.get_derived_type(Session)):  # proxy for frida.core.Session

    __super__: Session

    def __init__(self, session: Session, name: str = None):
        super().__init__(session)
        self._name: str = name or ""
        self._scripts: [FridaScript] = []

    @property
    def pid(self) -> int:
        return self._impl.pid

    @property
    def name(self) -> str:
        return self._name

    @property
    def scripts(self) -> ["FridaScript"]:
        return self._scripts

    @property
    def script(self) -> Optional["FridaScript"]:
        return self._scripts[0] if self._scripts else None

    @property
    def is_detached(self) -> bool:
        if hasattr(self.__super__, "is_detached"):
            return self.__super__.is_detached
        return False

    def append(self, script: "FridaScript"):
        if script not in self._scripts:
            self._scripts.append(script)

    def pop(self) -> Optional["FridaScript"]:
        if self._scripts:
            return self._scripts.pop()
        return None

    def __repr__(self):
        return f"Session(pid={self.pid}, name={self.name})" \
            if self.name \
            else f"Session(pid={self.pid})"

    __str__ = __repr__


class FridaScript(utils.get_derived_type(Script)):  # proxy for frida.core.Script

    __super__: Script

    def __init__(self, session: FridaSession, script: Script):
        super().__init__(script)
        self._session: FridaSession = session
        self._message_handler = None
        self._destroyed_handler = None
        self._session.append(self)

    @property
    def session(self) -> FridaSession:
        return self._session

    @property
    def exports_sync(self):
        if hasattr(self.__super__, "exports_sync"):
            return self.__super__.exports_sync
        return self.__super__.exports

    def add_message_handler(self, handler: "FridaScriptHandler"):
        self.remove_message_handler()
        self._message_handler = lambda msg, data: handler.on_script_message(self, msg, data)
        self.on("message", self._message_handler)

    def remove_message_handler(self):
        if self._message_handler is not None:
            self.off("message", self._message_handler)
            self._message_handler = None

    def add_destroyed_handler(self, handler: "FridaScriptHandler"):
        self.remove_destroyed_handler()
        self._destroyed_handler = lambda: handler.on_script_destroyed(self)
        self.on("destroyed", self._destroyed_handler)

    def remove_destroyed_handler(self):
        if self._destroyed_handler is not None:
            self.off("destroyed", self._destroyed_handler)
            self._destroyed_handler = None

    def __repr__(self):
        return f"Script(pid={self.session.pid}, name={self.session.name})" \
            if self.session.name \
            else f"Script(pid={self.session.pid})"

    __str__ = __repr__


class FridaScriptHandler(metaclass=abc.ABCMeta):
    class LogLevel:
        DEBUG = "debug"
        INFO = "info"
        WARNING = "warning"
        ERROR = "error"

    def on_script_message(self, script: FridaScript, message: Any, data: Any):
        """
        脚本消息回调函数，默认按照格式打印
        :param script: frida的脚本
        :param message: frida server发送的数据
        :param data: frida server发送的data
        """

        if utils.get_item(message, "type") == "send":
            payload = utils.get_item(message, "payload")
            if payload and isinstance(payload, dict):

                # 单独解析Emitter发出来的消息
                events = payload.pop("$events", None)
                if events:
                    for event in events:
                        # 如果消息类型是log，那就直接调on_log
                        log = event.pop("log", None)
                        if log is not None:
                            level = log.get("level") or self.LogLevel.DEBUG
                            message = log.get("message")
                            self.on_script_log(script, level, message, data)
                        # 如果只是普通消息，则调用on_event
                        msg = event.pop("msg", None)
                        if msg is not None:
                            self.on_script_event(script, msg, data)

                    return

            # 其他类型调用on_script_send方法解析
            if payload or data:
                self.on_script_send(script, payload, data)
                return

        elif utils.get_item(message, "type") == "error":
            stack = utils.get_item(message, "stack")
            self.on_script_log(script, self.LogLevel.ERROR, stack if stack else message, data)
            return

        else:
            self.on_script_log(script, self.LogLevel.WARNING, message, data)
            return

    def on_script_log(self, script: FridaScript, level: str, message: Any, data: Any):
        """
        脚本打印日志回调
        :param script: frida的脚本
        :param level: 日志级别
        :param message: 日志内容
        :param data: 事件数据
        """
        log_fn = _logger.debug
        if level == self.LogLevel.INFO:
            log_fn = _logger.info
        if level == self.LogLevel.WARNING:
            log_fn = _logger.warning
        if level == self.LogLevel.ERROR:
            log_fn = _logger.error

        if not utils.is_empty(message):
            log_fn(message)

    def on_script_event(self, script: FridaScript, message: Any, data: Any):
        """
        脚本发送事件回调
        :param script: frida的脚本
        :param message: 事件消息
        :param data: 事件带回来的数据
        """
        message = f"{script} event: {os.linesep}" \
                  f"{json.dumps(message, indent=2, ensure_ascii=False)}"
        self.on_script_log(script, self.LogLevel.INFO, message, None)

    def on_script_send(self, script: FridaScript, payload: Any, data: Any):
        """
        脚本调用send是收到的回调，例send({trace: "xxx"}, null)
        :param script: frida的脚本
        :param payload: 上述例子的{trace: "xxx"}
        :param data: 上述例子的null
        """
        message = f"{script} send: {os.linesep}" \
                  f"{payload}"
        self.on_script_log(script, self.LogLevel.INFO, message, data)

    def on_script_destroyed(self, script: FridaScript):
        """
        脚本结束回调函数，默认只打印log
        :param script: frida的脚本
        """
        self.on_script_log(script, self.LogLevel.INFO, f"{script} destroyed.", None)


class FridaApplication(FridaScriptHandler):
    """
    ----------------------------------------------------------------------

    eg.
        #!/usr/bin/env python3
        # -*- coding: utf-8 -*-

        from linktools.frida import FridaApplication, FridaEvalCode
        from linktools.frida.android import AndroidFridaServer


        jscode = \"\"\"
        Java.perform(function () {
            JavaHelper.hookMethods(
                "java.util.HashMap", "put", JavaHelper.getEventImpl({stack: false, args: true})
            );
        });
        \"\"\"

        if __name__ == "__main__":

            with AndroidFridaServer() as server:

                app = FridaApplication(
                    server,
                    user_scripts=(FridaEvalCode(jscode),),
                    enable_spawn_gating=True
                )

                for target_app in app.enumerate_applications():
                    if target_app.identifier == "com.topjohnwu.magisk":
                        app.load_script(target_app.pid)

                app.run()

    ----------------------------------------------------------------------
    """

    def __init__(
            self,
            device: Union[frida.core.Device, "FridaServer"],
            user_parameters: Dict[str, any] = None,
            user_scripts: Collection[FridaUserScript] = None,
            enable_spawn_gating: bool = False,
            enable_child_gating: bool = False,
            eternalize: str = False,
    ):
        self._device = device

        self._cb_spawn_added = lambda spawn: threading.Thread(target=self.on_spawn_added, args=(spawn,)).start()
        self._cb_spawn_removed = lambda spawn: self._reactor.schedule(lambda: self.on_spawn_removed(spawn))
        self._cb_child_added = lambda child: self._reactor.schedule(lambda: self.on_child_added(child))
        self._cb_child_removed = lambda child: self._reactor.schedule(lambda: self.on_child_removed(child))
        self._cb_output = lambda pid, fd, data: self._reactor.schedule(lambda: self.on_output(pid, fd, data))
        self._cb_lost = lambda: self._reactor.schedule(lambda: self.on_device_lost())

        self._last_error = None
        self._stop_request = utils.InterruptableEvent()
        self._finished = utils.InterruptableEvent()
        self._reactor = utils.Reactor(
            on_stop=self._on_stop,
            on_error=self._on_error
        )

        self._lock = threading.RLock()
        self._sessions: Dict[int, FridaSession] = {}
        self._last_change_id = 0
        self._monitored_files: Dict[str, frida.FileMonitor] = {}

        self._internal_script = FridaScriptFile(resource.get_asset_path("frida.min.js"))
        self._internal_debug_script = FridaScriptFile(resource.get_asset_path("frida.js"))

        self._user_parameters = user_parameters or {}
        self._user_scripts = user_scripts or tuple()

        self._enable_spawn_gating = enable_spawn_gating
        self._enable_child_gating = enable_child_gating
        self._eternalize = eternalize

        self._event_counter = Counter()

    @property
    def device(self) -> frida.core.Device:
        return self._device

    def _init(self):
        _logger.debug(f"FridaApplication init")

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
        _logger.debug(f"FridaApplication deinit")

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
            return {pid: session for pid, session in self._sessions.items() if not session.is_detached}

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
        if _logger.isEnabledFor(logging.DEBUG):
            script_files.append(FridaEvalCode("Log.setLevel(Log.DEBUG);"))
        elif _logger.isEnabledFor(logging.INFO):
            script_files.append(FridaEvalCode("Log.setLevel(Log.INFO);"))
        elif _logger.isEnabledFor(logging.WARNING):
            script_files.append(FridaEvalCode("Log.setLevel(Log.WARNING);"))
        elif _logger.isEnabledFor(logging.ERROR):
            script_files.append(FridaEvalCode("Log.setLevel(Log.ERROR);"))

        for user_script in self._user_scripts:
            script_files.append(user_script)

        return [o.to_dict() for o in script_files]

    def _load_script(self, pid: int, resume: bool = False):
        _logger.debug(f"Attempt to load script: pid={pid}, resume={resume}")

        session = self._attach_session(pid)
        self._unload_script(session)

        # read the internal script as an entrance
        source = self._internal_debug_script.source \
            if environ.debug \
            else self._internal_script.source

        script_kwargs = {}
        if utils.parse_version(frida.__version__) < (14,):
            script_kwargs["runtime"] = "v8"
        script = FridaScript(session, session.create_script(source, **script_kwargs))
        script.add_message_handler(self)
        script.add_destroyed_handler(self)

        try:
            script.load()
            script.exports_sync.load_scripts(self._load_script_files(), self._user_parameters)
        finally:
            if resume:
                utils.ignore_error(self.device.resume, pid)

        self._reactor.schedule(lambda: self.on_script_loaded(script))

    def _attach_session(self, pid: int):
        with self._lock:
            session = self._sessions.get(pid)
            if session is not None:
                if not session.is_detached:
                    return session
                self._sessions.pop(pid)

        _logger.debug(f"Attempt to attach process: pid={pid}")

        target_process = None
        for process in self.device.enumerate_processes():
            if process.pid == pid:
                target_process = process
        if target_process is None:
            raise frida.ProcessNotFoundError(f"unable to find process with pid '{pid}'")

        session = self.device.attach(target_process.pid)
        session = FridaSession(session, target_process.name)
        with self._lock:
            self._sessions[target_process.pid] = session

        def on_session_detached(reason, crash):
            with self._lock:
                self._sessions.pop(pid, None)
            self._reactor.schedule(lambda: self.on_session_detached(session, reason, crash))

        if self._enable_child_gating:
            _logger.debug(f"Enable child gating: {pid}")
            session.enable_child_gating()

        session.on("detached", on_session_detached)
        self._reactor.schedule(lambda: self.on_session_attached(session))

        return session

    def _detach_session(self, session: FridaSession):
        if session is not None:
            _logger.debug(f"{session} detach")
            utils.ignore_error(session.detach)

    def _unload_script(self, session: FridaSession):
        if not session:
            return
        while True:
            script = session.pop()
            if not script:
                break
            _logger.debug(f"{script} unload")
            utils.ignore_error(script.unload)

    def _eternalize_script(self, session: FridaSession):
        if not session:
            return
        while True:
            script = session.pop()
            if not script:
                break
            _logger.debug(f"{script} eternalize")
            utils.ignore_error(script.eternalize)

    def _monitor_all(self):

        def monitor_file(file: FridaScriptFile):
            _logger.debug(f"Monitor file: {file.path}")
            monitor = frida.FileMonitor(file.path)
            monitor.on("change", lambda changed_file, other_file, event_type: on_change_handler(event_type, file))
            monitor.enable()
            return monitor

        def on_change_handler(event_type, changed_file):
            if event_type == "changes-done-hint":
                _logger.debug(f"Monitor event: {event_type}, file: {changed_file}")
                self._last_change_id += 1
                change_id = self._last_change_id
                changed_file.clear()
                self._reactor.schedule(lambda: on_change_schedule(change_id, changed_file), delay=0.5)

        def on_change_schedule(change_id, changed_file):
            if change_id == self._last_change_id:
                self.on_file_change(changed_file)

        script_files = []
        for user_script in self._user_scripts:
            if isinstance(user_script, FridaScriptFile):
                script_files.append(user_script)
        if environ.debug:
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
        _logger.debug("Application stopped")

    def _on_error(self, exc, traceback):
        self._last_error = exc
        self.on_error(exc, traceback)

    def on_error(self, exc, traceback):
        if isinstance(exc, (KeyboardInterrupt, frida.TransportError, frida.ServerNotRunningError)):
            _logger.error(f"{traceback if environ.debug else exc}")
            self.stop()
        elif isinstance(exc, (frida.core.RPCException,)):
            _logger.error(f"{exc}")
        else:
            _logger.error(f"{traceback if environ.debug else exc}")

    def raise_on_error(self):
        if self._last_error is not None:
            raise self._last_error

    def on_output(self, pid: int, fd, data):
        _logger.debug(f"Output: pid={pid}, fd={fd}, data={data}")

    def on_device_lost(self):
        _logger.info("Device lost")
        self.stop()

    def on_file_change(self, file: FridaScriptFile):
        """
        脚本文件改变回调，默认重新加载脚本
        :param file: 脚本文件路径
        """
        _logger.debug(f"{file} changed")
        for session in self.sessions.values():
            self.load_script(session.pid)

    def on_spawn_added(self, spawn: "_frida.Spawn"):
        """
        spaw进程添加回调，默认resume所有spawn进程
        :param spawn: spawn进程信息
        """
        _logger.debug(f"{spawn} added")
        self.device.resume(spawn.pid)

    def on_spawn_removed(self, spawn: "_frida.Spawn"):
        """
        spaw进程移除回调，默认只打印log
        :param spawn: spawn进程信息
        """
        _logger.debug(f"{spawn} removed")

    def on_child_added(self, child: "_frida.Child"):
        """
        子进程添加回调，默认resume所有子进程
        :param child: 子进程信息
        """
        _logger.debug(f"{child} added")
        self.device.resume(child.pid)

    def on_child_removed(self, child: "_frida.Child"):
        """
        子进程移除回调，默认只打印log
        :param child: 子进程信息
        """
        _logger.debug(f"{child} removed")

    def on_script_loaded(self, script: FridaScript):
        """
        脚本加载回调，默认只打印log
        :param script: frida的脚本
        """
        _logger.debug(f"{script} loaded")

    def on_script_destroyed(self, script: FridaScript):
        """
        脚本结束回调函数，默认只打印log
        :param script: frida的脚本
        """
        _logger.debug(f"{script} destroyed")

    def on_script_event(self, script: FridaScript, message: Any, data: Any):
        """
        脚本发送事件回调
        :param script: frida的脚本
        :param message: 事件消息
        :param data: 事件数据
        """
        group = Counter.Group(accept_empty=False)
        count = self._event_counter.increase(
            group.add(
                pid=script.session.pid,
                method=utils.get_item(message, "method_name"),
            )
        )

        _logger.info(
            f"{script} event count={count} in the {group}: {os.linesep}"
            f"{json.dumps(message, indent=2, ensure_ascii=False)}",
        )

    def on_script_send(self, script: FridaScript, payload: Any, data: Any):
        """
        脚本调用send是收到的回调，例send({trace: "xxx"}, null)
        :param script: frida的脚本
        :param payload: 上述例子的{trace: "xxx"}
        :param data: 上述例子的null
        """
        _logger.info(f"{script} send, payload={payload}")

    def on_session_attached(self, session: FridaSession):
        """
        会话建立连接回调函数，默认只打印log
        :param session: 附加的会话
        """
        _logger.info(f"{session} attached")

    def on_session_detached(self, session: FridaSession, reason: str, crash: "_frida.Crash"):
        """
        会话结束回调函数，默认只打印log
        :param session: 结束的会话
        :param reason: 结束原因
        :param crash: crash信息
        """
        _logger.info(f"{session} detached, reason={reason}")
