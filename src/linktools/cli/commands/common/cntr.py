#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
@author  : Hu Ji
@file    : container.py 
@time    : 2024/3/21
@site    : https://github.com/ice-black-tea
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
from argparse import Namespace, ArgumentParser
from subprocess import SubprocessError
from typing import Optional, List, Type, Dict, Tuple, Any

import yaml
from git import GitCommandError

from linktools import environ, ConfigError, utils
from linktools.cli import BaseCommand, subcommand, SubCommandWrapper, subcommand_argument, SubCommandGroup, \
    BaseCommandGroup
from linktools.cli.argparse import KeyValueAction, BooleanOptionalAction, ParserCompleter
from linktools.container import ContainerManager, ContainerError
from linktools.rich import confirm, choose

manager = ContainerManager(environ)


def _iter_container_names():
    return [container.name for container in manager.containers.values()]


def _iter_installed_container_names():
    return [container.name for container in manager.get_installed_containers()]


class RepoCommand(BaseCommandGroup):
    """
    manage container repository
    """

    @property
    def name(self):
        return "repo"

    @subcommand("list", help="list repositories")
    def on_command_list(self):
        repos = manager.get_all_repos()
        for key, value in repos.items():
            data = {key: value}
            self.logger.info(
                yaml.dump(data, sort_keys=False).strip()
            )

    @subcommand("add", help="add repository")
    @subcommand_argument("url", help="repository url")
    @subcommand_argument("-b", "--branch", help="branch name")
    @subcommand_argument("-f", "--force", help="force add")
    def on_command_add(self, url: str, branch: str = None, force: bool = False):
        manager.add_repo(url, branch=branch, force=force)

    @subcommand("update", help="update repositories")
    @subcommand_argument("-f", "--force", help="force update")
    def on_command_update(self, force: bool = False):
        manager.update_repos(force=force)

    @subcommand("remove", help="remove repository")
    @subcommand_argument("url", nargs="?", help="repository url")
    def on_command_remove(self, url: str = None):
        repos = list(manager.get_all_repos().keys())
        if not repos:
            raise ContainerError("No repository found")

        if url is None:
            index = choose("Choose repository you want to remove", repos)
            if not confirm(f"Remove repository `{repos[index]}`?", default=False):
                raise ContainerError("Canceled")
            manager.remove_repo(repos[index])

        elif url in repos:
            if not confirm(f"Remove repository `{url}`?", default=False):
                raise ContainerError("Canceled")
            manager.remove_repo(url)

        else:
            raise ContainerError(f"Repository `{url}` not found.")


class ConfigCommand(BaseCommand):
    """
    manage container configs
    """

    @property
    def name(self):
        return "config"

    def init_arguments(self, parser: ArgumentParser) -> None:
        self.add_subcommands(parser)

    def run(self, args: Namespace) -> Optional[int]:
        subcommand = self.parse_subcommand(args)
        if subcommand:
            return subcommand.run(args)
        containers = manager.prepare_installed_containers()
        manager.create_docker_compose_process(
            containers,
            "config",
            privilege=False,
        ).check_call()

    @subcommand("set", help="set container configs")
    @subcommand_argument("configs", action=KeyValueAction, nargs="+", help="container config key=value")
    def on_command_set(self, configs: Dict[str, str]):
        manager.config.save_cache(**configs)
        for key in sorted(configs.keys()):
            value = manager.config.get(key)
            self.logger.info(f"{key}: {value}")

    @subcommand("unset", help="remove container configs")
    @subcommand_argument("configs", action=KeyValueAction, metavar="KEY", nargs="+", help="container config keys")
    def on_command_remove(self, configs: Dict[str, str]):
        manager.config.remove_cache(*configs)
        self.logger.info(f"Unset {', '.join(configs)} success")

    @subcommand("list", help="list container configs")
    def on_command_list(self):
        keys = set()
        for container in manager.prepare_installed_containers():
            keys.update(container.configs.keys())
            if hasattr(container, "keys") and isinstance(container.keys, (Tuple, List, Dict)):
                keys.update([key for key in container.keys if key in manager.config])
        for key in sorted(keys):
            value = manager.config.get(key)
            self.logger.info(f"{key}: {value}")

    @subcommand("edit", help="edit the config file in an editor")
    @subcommand_argument("--editor", help="editor to use to edit the file")
    def on_command_edit(self, editor: str):
        return manager.create_process(editor, manager.config.cache_path).call()

    @subcommand("reload", help="reload container configs")
    def on_command_reload(self):
        manager.config.reload = True
        manager.prepare_installed_containers()


class ExecCommand(BaseCommand):
    """
    exec container command
    """

    @property
    def name(self):
        return "exec"

    @property
    def _subparser(self) -> ArgumentParser:
        parser = ArgumentParser()

        subcommands = []
        for container in manager.get_installed_containers():
            subcommand_group = SubCommandGroup(container.name, container.description)
            subcommands.append(subcommand_group)
            subcommands.extend(self.walk_subcommands(container, parent_id=subcommand_group.id))
        self.add_subcommands(parser, target=subcommands)

        return parser

    def init_arguments(self, parser: ArgumentParser) -> None:
        parser.add_argument("exec_name", nargs="?", metavar="CONTAINER", help="container name",
                            choices=utils.lazy_iter(_iter_installed_container_names))
        action = parser.add_argument("exec_args", nargs="...", metavar="ARGS", help="container exec args")

        if ParserCompleter:
            class Completer(ParserCompleter):
                get_parser = lambda _: self._subparser
                get_args = lambda _, args, **kw: [args.exec_name, *args.exec_args] if args.exec_name else None

            action.completer = Completer()

    def run(self, args: Namespace) -> Optional[int]:
        args = self._subparser.parse_args([args.exec_name, *args.exec_args] if args.exec_name else [])
        subcommand = self.parse_subcommand(args)
        if not subcommand or isinstance(subcommand, SubCommandGroup):
            return self.print_subcommands(args, root=subcommand, max_level=2)
        manager.prepare_installed_containers()
        return subcommand.run(args)


class Command(BaseCommandGroup):
    """
    Deploy and manage Docker/Podman containers with ease
    """

    @property
    def known_errors(self) -> List[Type[BaseException]]:
        return super().known_errors + [
            ContainerError, ConfigError, SubprocessError, GitCommandError, OSError
        ]

    def init_subcommands(self) -> Any:
        return [
            self,
            SubCommandWrapper(ExecCommand()),
            SubCommandWrapper(ConfigCommand()),
            SubCommandWrapper(RepoCommand()),
        ]

    @subcommand("list", help="list all containers")
    def on_command_list(self):
        install_containers = manager.get_installed_containers(resolve=False)
        all_install_containers = manager.resolve_depend_containers(install_containers)
        for container in sorted(manager.containers.values(), key=lambda o: o.order):
            if container not in all_install_containers:
                self.logger.info(f"[ ] {container.name}", extra={"style": "dim"})
            elif container in install_containers:
                self.logger.info(f"[*] {container.name} [added]", extra={"style": "red bold"})
            else:
                self.logger.info(f"[-] {container.name} [dependency]", extra={"style": "red dim"})

    @subcommand("add", help="add containers to installed list")
    @subcommand_argument("names", metavar="CONTAINER", nargs="+", help="container name",
                         choices=utils.lazy_iter(_iter_container_names))
    def on_command_add(self, names: List[str]):
        containers = manager.add_installed_containers(*names)
        if not containers:
            raise ContainerError("No container added")
        result = sorted(list([container.name for container in containers]))
        self.logger.info(f"Add {', '.join(result)} success")

    @subcommand("remove", help="remove containers from installed list")
    @subcommand_argument("-f", "--force", help="Force remove")
    @subcommand_argument("names", metavar="CONTAINER", nargs="+", help="container name",
                         choices=utils.lazy_iter(_iter_container_names))
    def on_command_remove(self, names: List[str], force: bool = False):
        containers = manager.remove_installed_containers(*names, force=force)
        if not containers:
            raise ContainerError("No container removed")
        result = sorted(list([container.name for container in containers]))
        self.logger.info(f"Remove {', '.join(result)} success")

    @subcommand("info", help="display container info")
    @subcommand_argument("names", metavar="CONTAINER", nargs="+", help="container name",
                         choices=utils.lazy_iter(_iter_container_names))
    def on_command_info(self, names: List[str]):
        for name in names:
            container = manager.containers[name]
            data = {
                name: {
                    "path": container.root_path,
                    "order": container.order,
                    "enable": container.enable,
                    "dependencies": container.dependencies,
                    "configs": list(set(container.configs.keys())),
                    "exposes": list(set([o.name for o in container.exposes])),
                }
            }
            self.logger.info(yaml.dump(data, sort_keys=False).strip())

    @subcommand("up", help="deploy installed containers")
    @subcommand_argument("--build", action=BooleanOptionalAction, help="build images before starting")
    @subcommand_argument("--pull", help="pull image before running", choices=["always", "missing", "never"])
    @subcommand_argument("name", metavar="CONTAINER", nargs="?", help="container name",
                         choices=utils.lazy_iter(_iter_installed_container_names))
    def on_command_up(self, name: str = None, build: str = True, pull: str = None):
        containers = manager.prepare_installed_containers()
        target_containers = [c for c in containers if not name or c.name == name]

        options = ["--detach"]
        if build:
            options.extend(["--build"])
        if pull:
            options.extend(["--pull", pull])

        services = []
        if name:
            services.extend(manager.containers[name].services.keys())
            if not services:
                raise ContainerError(f"No service found in container `{name}`")
        else:
            options.extend(["--remove-orphans"])

        for container in target_containers:
            container.on_starting()
        manager.create_docker_compose_process(
            containers,
            "up", *options, *services
        ).check_call()
        for container in reversed(target_containers):
            container.on_started()

    @subcommand("restart", help="restart installed containers")
    @subcommand_argument("--build", action=BooleanOptionalAction, help="build images before starting")
    @subcommand_argument("--pull", help="pull image before running", choices=["always", "missing", "never"])
    @subcommand_argument("name", metavar="CONTAINER", nargs="?", help="container name",
                         choices=utils.lazy_iter(_iter_installed_container_names))
    def on_command_restart(self, name: str = None, build: str = True, pull: str = None):
        containers = manager.prepare_installed_containers()
        target_containers = [c for c in containers if not name or c.name == name]

        options = ["--detach"]
        if build:
            options.extend(["--build"])
        if pull:
            options.extend(["--pull", pull])

        services = []
        if name:
            services.extend(manager.containers[name].services.keys())
            if not services:
                raise ContainerError(f"No service found in container `{name}`")
        else:
            options.extend(["--remove-orphans"])

        for container in reversed(target_containers):
            container.on_stopping()
        manager.create_docker_compose_process(
            containers,
            "stop", *services
        ).check_call()
        for container in target_containers:
            container.on_stopped()

        for container in target_containers:
            container.on_starting()
        manager.create_docker_compose_process(
            containers,
            "up", *options, *services
        ).check_call()
        for container in reversed(target_containers):
            container.on_started()

    @subcommand("down", help="stop installed containers")
    @subcommand_argument("name", metavar="CONTAINER", nargs="?", help="container name",
                         choices=utils.lazy_iter(_iter_installed_container_names))
    def on_command_down(self, name: str = None):
        containers = manager.prepare_installed_containers()
        target_containers = [c for c in containers if not name or c.name == name]

        services = []
        if name:
            services.extend(manager.containers[name].services.keys())
            if not services:
                raise ContainerError(f"No service found in container `{name}`")

        for container in reversed(target_containers):
            container.on_stopping()
        manager.create_docker_compose_process(
            containers,
            "down", *services
        ).check_call()
        for container in target_containers:
            container.on_stopped()

        for container in target_containers:
            container.on_removed()


command = Command()
if __name__ == '__main__':
    command.main()
