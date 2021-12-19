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
import collections
import threading
import time
from typing import Optional, Union

import _frida
import frida
from colorama import Fore

from linktools import utils, resource, logger
from linktools.decorator import cached_property


class Reactor(object):
    """
    Code stolen from frida_tools.application.Reactor
    """

    def __init__(self, run_until_return, on_stop=None):
        self._running = False
        self._run_until_return = run_until_return
        self._on_stop = on_stop
        self._pending = collections.deque([])
        self._lock = threading.Lock()
        self._cond = threading.Condition(self._lock)

        self.io_cancellable = frida.Cancellable()

        self.ui_cancellable = frida.Cancellable()
        self._ui_cancellable_fd = self.ui_cancellable.get_pollfd()

    def __del__(self):
        self._ui_cancellable_fd.release()

    def is_running(self):
        with self._lock:
            return self._running

    def run(self):
        with self._lock:
            self._running = True

        worker = threading.Thread(target=self._run)

        try:
            worker.start()
            self._run_until_return(self)
        finally:
            self.stop()
            worker.join(60)

    def _run(self):
        running = True
        while running:
            now = time.time()
            work = None
            timeout = None
            previous_pending_length = -1
            with self._lock:
                for item in self._pending:
                    (f, when) = item
                    if now >= when:
                        work = f
                        self._pending.remove(item)
                        break
                if len(self._pending) > 0:
                    timeout = max([min(map(lambda item: item[1], self._pending)) - now, 0])
                previous_pending_length = len(self._pending)

            if work is not None:
                with self.io_cancellable:
                    try:
                        work()
                    except frida.OperationCancelledError:
                        pass

            with self._lock:
                if self._running and len(self._pending) == previous_pending_length:
                    self._cond.wait(timeout)
                running = self._running

        if self._on_stop is not None:
            self._on_stop()

        self.ui_cancellable.cancel()

    def stop(self):
        self.schedule(self._stop)

    def _stop(self):
        with self._lock:
            self._running = False

    def schedule(self, f, delay=None):
        now = time.time()
        if delay is not None:
            when = now + delay
        else:
            when = now
        with self._lock:
            self._pending.append((f, when))
            self._cond.notify()

    def cancel_io(self):
        self.io_cancellable.cancel()


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
            Java.perform(function () {
                var $ = new JavaHelper();
                $.hookMethods(
                    "java.util.HashMap", "put", $.getHookImpl({printStack: false, printArgs: true})
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
            user_script: str = None,
            eval_code: str = None,
            enable_spawn_gating=False,
            enable_child_gating=False,
            eternalize=False,
            debug=False):
        """
        :param server: 环境信息
        """
        self.device: frida.core.Device = device

        self._stop_requested = threading.Event()
        self._reactor = Reactor(
            run_until_return=self._run,
            on_stop=self._on_stop
        )

        self._debug = debug
        self._persist_script = resource.get_persist_path("frida.min.js")
        self._persist_debug_script = resource.get_persist_path("frida.js")

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
        # self.device.on('uninjected', xxx)
        # self.device.on('lost', xxx)

        if self._enable_spawn_gating:
            self.device.enable_spawn_gating()

    def run(self):
        try:
            self._monitor_all()
            self._reactor.run()
        finally:
            self._demonitor_all()

    def _run(self, reactor):
        try:
            self._stop_requested.wait()
        finally:
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

    @classmethod
    def _read_script(cls, path):
        with codecs.open(path, 'rb', 'utf-8') as f:
            return f.read()

    @cached_property
    def _persist_code(self):
        return self._read_script(self._persist_script)

    def _load_script(self, pid: int, resume: bool = False):
        logger.debug(f"Attempt to load script: pid={pid}, resume={resume}", tag="[✔]")

        codes = []
        if self._debug:
            codes.append(self._read_script(self._persist_debug_script))
        else:
            codes.append(self._persist_code)

        if self._user_script is not None:
            codes.append(self._read_script(self._user_script))

        if self._eval_code is not None:
            codes.append(self._eval_code)

        try:
            session = self._attach_session(pid)
            if session is None:
                logger.warning(f"Attach session failed, skip loading script", tag="[!]", fore=Fore.RED)
                return

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
            logger.warning(f"Load script error: {e}", tag="[!]", fore=Fore.RED)

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
            logger.warning(f"Attach session error: {e}", tag="[!]", fore=Fore.RED)

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

        paths = [self._user_script]
        if self._debug:
            paths.append(self._persist_debug_script)

        for path in paths:
            if path is not None and path not in self._monitored_files:
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
