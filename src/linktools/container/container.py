#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
@author  : Hu Ji
@file    : deploy.py 
@time    : 2023/05/21
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
   /  oooooooooooooooo  .o.  oooo /,   `,"-----------
  / ==ooooooooooooooo==.o.  ooo= //   ,``--{)B     ,"
 /_==__==========__==_ooo__ooo=_/'   /___________,"
"""
import os
import pathlib
import re
import textwrap
from typing import TYPE_CHECKING, Dict, Any, List, Optional, Callable

import yaml
from jinja2 import Environment, TemplateError

from .. import utils, Config
from ..cli import subcommand, subcommand_argument
from ..decorator import cached_property
from ..rich import choose

if TYPE_CHECKING:
    from .manager import ContainerManager


class ExposeCategory:

    def __init__(self, name: str, desc: str):
        self.name = name
        self.desc = desc

    def __call__(self, name: str, icon: str, desc: str, url: str):
        return ExposeLink(self, name, icon, desc or name, url)


class ExposeLink:

    def __init__(self, category: ExposeCategory, name: str, icon: str, desc: str, url: str):
        self.category = category
        self.name = name
        self.icon = icon
        self.desc = desc
        self.url = url

    @property
    def is_valid(self) -> bool:
        return not not self.url


class ExposeMixin:
    expose_public = ExposeCategory("public", "Public")
    expose_private = ExposeCategory("private", "Private")
    expose_container = ExposeCategory("container", "Container")
    expose_other = ExposeCategory("other", "Other")

    def load_config_url(self: "BaseContainer", key: str, *path: str):
        url = self.manager.config.get(key, type=str, default=None)
        if url:
            return utils.make_url(url, *path)
        return None

    def load_port_url(self: "BaseContainer", key: str, *path: str, https: bool = True):
        port = self.manager.config.get(key, type=int, default=0)
        if 0 < port < 65535:
            return utils.make_url(f"{'https' if https else 'http'}://{self.manager.host}:{port}", *path)
        return None

    def load_nginx_url(self: "BaseContainer", key: str, *path: str, https: bool = True):
        domain = self.manager.config.get(key, type=str, default=None)
        if domain:
            port = self.manager.config.get("HTTPS_PORT" if https else "HTTP_PORT", type=int)
            return utils.make_url(f"{'https' if https else 'http'}://{domain}:{port}/", *path)
        return None


class NginxMixin:

    def get_nginx_domain(self: "BaseContainer", name: str = None):

        def get_domain(cfg: Config):
            if not self.manager.containers["nginx"].enable:
                return ""
            if not cfg.get("WILDCARD_DOMAIN", type=bool):
                return cfg.get("ROOT_DOMAIN")
            root_domain = cfg.get("ROOT_DOMAIN")
            if root_domain in ("_", "0.0.0.0"):
                return root_domain
            if name is None:
                return f"{self.name}.{root_domain}"
            elif name.strip() == "":
                return root_domain
            return f"{name}.{root_domain}"

        return Config.Lazy(get_domain)

    def write_nginx_conf(self: "BaseContainer", domain: str, template: str, name: str = None, https: bool = True):
        nginx = self.manager.containers["nginx"]
        if domain and nginx.enable:
            if not self.manager.config.get("HTTPS_ENABLE", type=bool):
                https = False
            self.render_template(
                nginx.get_path("https.conf" if https else "http.conf"),
                nginx.get_app_path("temporary", self.name, f"{domain}.conf", create_parent=True),
                DOMAIN=domain
            )
            self.render_template(
                template,
                nginx.get_app_path("temporary", self.name, f"{domain}_confs", f"{name or self.name}.conf",
                                   create_parent=True),
                DOMAIN=domain
            )


class ContainerError(Exception):
    pass


class ContainerTemplateError(ContainerError):
    pass


class AbstractMetaClass(type):

    def __new__(mcs, name, bases, namespace):
        if "__abstract__" not in namespace:
            namespace["__abstract__"] = False
        return super().__new__(mcs, name, bases, namespace)


class BaseContainer(ExposeMixin, NginxMixin, metaclass=AbstractMetaClass):
    __abstract__ = True

    def __init__(self, manager: "ContainerManager", root_path: str, name: str = None):
        name = name or self.__module__
        index = name.rfind(".")
        if index >= 0:
            name = name[index + 1:]
        match = re.match(r"^(\d{1,3})-(.*)$", name, re.M | re.I)
        if match:
            self._order = int(match.group(1))
            self._name = match.group(2)
        else:
            self._order = 900
            self._name = name
        self._enable = False
        self.manager = manager
        self.logger = manager.logger
        self.root_path = root_path

    @property
    def name(self) -> str:
        return self._name

    @cached_property
    def description(self) -> str:
        return textwrap.dedent((self.__doc__ or "").strip())

    @property
    def order(self) -> int:
        return self._order

    @property
    def enable(self) -> bool:
        return self._enable

    @enable.setter
    def enable(self, value: bool):
        self._enable = value

    @property
    def dependencies(self) -> [str]:
        return []

    @property
    def configs(self) -> Dict[str, Any]:
        return {}

    @property
    def exposes(self) -> List[ExposeLink]:
        return []

    @cached_property
    def docker_compose(self) -> Optional[Dict[str, Any]]:
        for name in self.manager.docker_compose_names:
            path = self.get_path(name)
            if not os.path.exists(path):
                continue
            data = self.render_template(path)
            data = yaml.safe_load(data)
            if "services" in data and isinstance(data["services"], dict):
                for name, service in data["services"].items():
                    if not isinstance(service, dict):
                        continue
                    service.setdefault("container_name", name)
                    service.setdefault("restart", "unless-stopped")
                    service.setdefault("logging", {
                        "driver": "json-file",
                        "options": {
                            "max-size": "10m",
                        }
                    })
                    if "image" not in service and "build" not in service:
                        path = self.get_docker_file_path()
                        if path and os.path.exists(path):
                            service["build"] = {
                                "context": self.get_docker_context_path(),
                                "dockerfile": path
                            }
                    if "env_file" not in service:
                        path = self.get_path(".env")
                        if path and os.path.exists(path):
                            service["env_file"] = [
                                path
                            ]
                return data
        return None

    @cached_property
    def docker_file(self) -> Optional[str]:
        path = self.get_path("Dockerfile")
        if os.path.exists(path):
            return self.render_template(path)
        return None

    @cached_property
    def services(self) -> Dict[str, Dict[str, Any]]:
        services: dict = utils.get_item(self.docker_compose, "services")
        if not services or not isinstance(services, dict):
            return {}
        return services

    @cached_property
    def start_hooks(self) -> List[Callable[[], Any]]:
        return []

    @cached_property
    def stop_hooks(self) -> List[Callable[[], Any]]:
        return []

    def on_init(self):
        pass

    def on_starting(self):
        pass

    def on_started(self):
        pass

    def on_stopping(self):
        pass

    def on_stopped(self):
        pass

    def on_removed(self):
        pass

    @subcommand("shell", help="exec into container using command sh")
    @subcommand_argument("-c", "--command", help="shell command")
    @subcommand_argument("--privileged", help="give extended privileges to the command")
    @subcommand_argument("-u", "--user", help="Username or UID (format: \"<name|uid>[:<group|gid>]\")")
    def on_exec_shell(self, command: str = None, privileged: bool = False, user: str = None):
        service = self.choose_service()

        options = []
        if privileged:
            options.append("--privileged")
        if user:
            options.append("--user")
            options.append(user)

        if not command:
            commands = []
            for shell in ["/bin/zsh", "/bin/fish", "/bin/bash", "/bin/ash", "/bin/sh"]:
                shell_command = [
                    "if" if len(commands) == 0 else "elif", "[", "-x", shell, "]", ";",
                    "then", shell, ";",
                ]
                commands.extend(shell_command)
            commands.extend(["else", "sh", ";"])
            commands.append("fi")
            commands = ("sh", "-c", utils.list2cmdline(commands))
        else:
            commands = utils.cmdline2list(command)

        return self.manager.create_docker_process(
            "exec", "-it", *options, service.get("container_name"), *commands
        ).call()

    @subcommand("logs", help="fetch the logs of container")
    @subcommand_argument("-f", "--follow",
                         help="follow log output")
    @subcommand_argument("-t", "--timestamps",
                         help="show timestamps")
    @subcommand_argument("-n", "--tail", metavar="string",
                         help="number of lines to show from the end of the logs (default \"all\")")
    @subcommand_argument("--since", metavar="string",
                         help="show logs since timestamp (e.g. \"2013-01-02T13:23:37Z\") or relative (e.g. \"42m\" for 42 minutes)")
    @subcommand_argument("--until", metavar="string",
                         help="show logs before a timestamp (e.g. \"2013-01-02T13:23:37Z\") or relative (e.g. \"42m\" for 42 minutes)")
    def on_exec_logs(self, follow: bool = True, tail: str = None, timestamps: bool = True,
                     since: str = None, until: str = None):
        service = self.choose_service()

        options = []
        if follow:
            options.append("--follow")
        if timestamps:
            options.append("--timestamps")
        if tail:
            options.append("--tail")
            options.append(tail)
        if since:
            options.append("--since")
            options.append(since)
        if until:
            options.append("--until")
            options.append(until)
        return self.manager.create_docker_process(
            "logs", *options, service.get("container_name")
        ).call()

    def get_path(self, *paths: str) -> str:
        return utils.get_path(
            self.root_path,
            *paths
        )

    def get_app_path(self, *paths: str, create: bool = False, create_parent: bool = False) -> str:
        return utils.get_path(
            self.manager.app_path,
            self.name,
            *paths,
            create=create,
            create_parent=create_parent
        )

    def get_app_data_path(self, *paths: str, create: bool = False, create_parent: bool = False) -> str:
        return utils.get_path(
            self.manager.app_data_path,
            self.name,
            *paths,
            create=create,
            create_parent=create_parent
        )

    def get_user_data_path(self, *paths: str, create: bool = False, create_parent: bool = False) -> str:
        return utils.get_path(
            self.manager.user_data_path,
            *paths,
            create=create,
            create_parent=create_parent
        )

    def get_download_path(self, *paths: str, create: bool = False, create_parent: bool = False) -> str:
        return utils.get_path(
            self.manager.download_path,
            *paths,
            create=create,
            create_parent=create_parent
        )

    def get_temp_path(self, *paths: str, create: bool = False, create_parent: bool = False) -> str:
        return utils.get_path(
            self.manager.temp_path,
            "container",
            self.name,
            *paths,
            create=create,
            create_parent=create_parent
        )

    def choose_service(self) -> Optional[Dict[str, Any]]:
        services = list(self.services.values())
        if len(services) == 0:
            raise ContainerError(f"Not found any service in {self}")
        if len(services) == 1:
            return services[0]
        index = choose(
            "Please choose service",
            choices=[service.get("container_name") for service in services],
            default=0
        )
        return services[index]

    def get_docker_compose_file(self) -> Optional[str]:
        destination = None
        if self.docker_compose:
            destination = utils.get_path(
                self.manager.temp_path,
                "compose",
                f"{self.name}.yml",
                create_parent=True,
            )
            utils.write_file(
                destination,
                yaml.dump(self.docker_compose)
            )
        return destination

    def get_docker_file_path(self) -> Optional[str]:
        destination = None
        if self.docker_file:
            destination = utils.get_path(
                self.manager.temp_path,
                "dockerfile",
                f"{self.name}.Dockerfile",
                create_parent=True,
            )
            utils.write_file(
                destination,
                self.docker_file
            )
        return destination

    def get_docker_context_path(self) -> str:
        return self.get_path()

    def is_depend_on(self, name: str):
        next_items = set(self.dependencies)
        exclude_items = set()
        while next_items:
            if name in next_items:
                return True
            exclude_items.update(next_items)
            current_items = next_items
            next_items = set()
            for next_name in current_items:
                for next_dependency in self.manager.containers[next_name].dependencies:
                    if next_dependency not in exclude_items:
                        next_items.add(next_dependency)
        return False

    def render_template(self, source: str, destination: str = None, **kwargs: Any):
        config = self.manager.config

        context = {
            key: utils.lazy_load(config.get, key)
            for key in config.keys()
        }

        def mkdir(path: str):
            path = config.cast(path, type="path")
            self.start_hooks.append(lambda: os.makedirs(path, exist_ok=True))
            return path

        def chown(path: str, user: str = None):
            path = config.cast(path, type="path")
            if user:
                uid, gid = utils.get_uid(user), utils.get_gid(user)
                self.start_hooks.append(lambda: self.manager.change_file_owner(path, uid, gid))
            return path

        context.update(
            DEBUG=self.manager.debug,

            CONTAINER_PATH=utils.lazy_load(lambda: pathlib.Path(self.get_path())),
            APP_PATH=utils.lazy_load(lambda: pathlib.Path(self.get_app_path())),
            APP_DATA_PATH=utils.lazy_load(lambda: pathlib.Path(self.get_app_data_path())),
            USER_DATA_PATH=utils.lazy_load(lambda: pathlib.Path(self.get_user_data_path())),
            DOWNLOAD_PATH=utils.lazy_load(lambda: pathlib.Path(self.get_download_path())),

            manager=self.manager,
            container=self,
            config=config,
            user=self.manager.user,
            docker_user=utils.lazy_load(self.manager.config.get, "DOCKER_USER"),

            mkdir=mkdir,
            chown=chown,
        )

        context.update(kwargs)

        environment = Environment()
        environment.filters.update(
            mkdir=mkdir,
            chown=chown
        )

        try:
            self.logger.debug(f"{self} render template {source} to {destination}")
            template = environment.from_string(utils.read_file(source, text=True))
            result = template.render(context)
            if destination:
                utils.write_file(destination, result)
            return result

        except TemplateError as e:
            raise ContainerTemplateError(e)

    def __repr__(self):
        return f"Container<{self.name}>"


class SimpleContainer(BaseContainer):

    def __init__(self, manager: "ContainerManager", root_path: str):
        super().__init__(
            manager,
            root_path,
            name=os.path.basename(root_path)
        )
