"""Read-only host observations for the installer and doctor.

This module never creates databases, never restores dumps and never prints
credentials. Foreign SQL dumps outside the PLAIK backup directory are not
treated as restore sources.
"""

from __future__ import annotations

import os
import re
import stat
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from .config import CoreSettings
from .requirements import RequirementCheck


CommandRunner = Callable[[list[str]], tuple[int, str]]

_LISTENER_PORT = re.compile(r":(\d+)\s")
_LISTENER_PROCESS = re.compile(r'users:\(\("([^"]+)"')
_CLUSTER_LINE = re.compile(
    r"^(?P<version>\S+)\s+(?P<name>\S+)\s+(?P<port>\d+)\s+(?P<status>\S+)\s+"
)
_SAFE_DB_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_-]{0,62}$")


def _default_runner(command: list[str]) -> tuple[int, str]:
    try:
        completed = subprocess.run(
            command,
            check=False,
            capture_output=True,
            text=True,
            timeout=3,
        )
    except (OSError, subprocess.TimeoutExpired):
        return 1, ""
    return completed.returncode, completed.stdout


@dataclass(frozen=True, slots=True)
class PostgreSQLListener:
    host: str
    port: int
    process: str
    source: str


@dataclass(frozen=True, slots=True)
class PostgreSQLDatabaseObservation:
    port: int
    name: str
    application_tables: int | None
    inspectable: bool


@dataclass(frozen=True, slots=True)
class HostInventory:
    listeners: tuple[PostgreSQLListener, ...]
    databases: tuple[PostgreSQLDatabaseObservation, ...]
    backup_artifacts: int
    backups_dir: str
    backups_dir_safe: bool

    @property
    def suggested_listener(self) -> PostgreSQLListener | None:
        empty = {
            item.port
            for item in self.databases
            if item.inspectable
            and item.name == "plaik"
            and item.application_tables == 0
        }
        ranked: list[PostgreSQLListener] = []
        for listener in self.listeners:
            if listener.host not in {"127.0.0.1", "::1"}:
                continue
            if empty and listener.port not in empty:
                continue
            ranked.append(listener)
        ranked.sort(
            key=lambda item: (
                0 if item.process == "postgres" else 1,
                0 if item.port in empty else 1,
                item.port,
            )
        )
        return ranked[0] if ranked else None

    @property
    def suggested_database(self) -> str | None:
        listener = self.suggested_listener
        if listener is None:
            return None
        for item in self.databases:
            if (
                item.port == listener.port
                and item.inspectable
                and item.name == "plaik"
                and item.application_tables == 0
            ):
                return item.name
        return None

    def public_inventory(self) -> dict[str, object]:
        suggested = None
        listener = self.suggested_listener
        if listener is not None and self.suggested_database:
            suggested = {
                "host": listener.host,
                "port": listener.port,
                "database": self.suggested_database,
            }
        return {
            "suggested": suggested,
            "create_supported": any(
                item.process == "postgres" and item.host in {"127.0.0.1", "::1"}
                for item in self.listeners
            ),
            "restore_blocked": True,
        }

    def observations(self) -> tuple[RequirementCheck, ...]:
        if self.listeners:
            listener_detail = "; ".join(
                f"{item.host}:{item.port} process={item.process} source={item.source}"
                for item in self.listeners
            )
        else:
            listener_detail = "no loopback PostgreSQL listeners detected"
        if self.databases:
            database_detail = "; ".join(_database_detail(item) for item in self.databases)
        else:
            database_detail = (
                "local database names were not inspected; "
                "enter an already provisioned empty database"
            )
        if not self.backups_dir_safe:
            backup_detail = f"backup directory is unsafe: {self.backups_dir}"
        elif self.backup_artifacts:
            backup_detail = (
                f"{self.backup_artifacts} PLAIK backup artifact(s) in {self.backups_dir}; "
                "this installer does not restore them automatically"
            )
        else:
            backup_detail = (
                f"no PLAIK backup artifacts in {self.backups_dir}; "
                "foreign SQL dumps are not restore sources"
            )
        return (
            RequirementCheck("postgresql_listeners", True, listener_detail),
            RequirementCheck("postgresql_databases", True, database_detail),
            RequirementCheck("plaik_backups", True, backup_detail),
        )


def discover_host_inventory(
    settings: CoreSettings,
    *,
    runner: CommandRunner | None = None,
    euid: int | None = None,
) -> HostInventory:
    execute = runner or _default_runner
    listeners = _discover_listeners(execute)
    databases = _discover_databases(execute, listeners, euid=euid)
    backup_artifacts, backups_dir, backups_dir_safe = _discover_backups(settings)
    return HostInventory(
        listeners=listeners,
        databases=databases,
        backup_artifacts=backup_artifacts,
        backups_dir=backups_dir,
        backups_dir_safe=backups_dir_safe,
    )


def _discover_listeners(runner: CommandRunner) -> tuple[PostgreSQLListener, ...]:
    clusters = _discover_clusters(runner)
    by_port = {item.port: item for item in clusters}
    code, output = runner(["ss", "-ltnp"])
    if code != 0 or not output.strip():
        code, output = runner(["ss", "-ltn"])
    listeners: dict[int, PostgreSQLListener] = dict(by_port)
    for line in output.splitlines():
        if "127.0.0.1:" not in line and "[::1]:" not in line:
            continue
        port_match = _LISTENER_PORT.search(line.replace("[::1]", "127.0.0.1"))
        if port_match is None:
            continue
        port = int(port_match.group(1))
        process_match = _LISTENER_PROCESS.search(line)
        process = process_match.group(1) if process_match else "unknown"
        host = "127.0.0.1"
        if port in by_port:
            current = by_port[port]
            listeners[port] = PostgreSQLListener(
                host=current.host,
                port=port,
                process=process if process != "unknown" else current.process,
                source=current.source,
            )
            continue
        if process in {"postgres", "docker-proxy"} or port in by_port:
            listeners[port] = PostgreSQLListener(
                host=host,
                port=port,
                process=process,
                source="tcp",
            )
    return tuple(sorted(listeners.values(), key=lambda item: item.port))


def _discover_clusters(runner: CommandRunner) -> tuple[PostgreSQLListener, ...]:
    code, output = runner(["pg_lsclusters", "--no-header"])
    if code != 0:
        return ()
    found: list[PostgreSQLListener] = []
    for line in output.splitlines():
        match = _CLUSTER_LINE.match(line.strip())
        if match is None:
            continue
        found.append(
            PostgreSQLListener(
                host="127.0.0.1",
                port=int(match.group("port")),
                process="postgres",
                source=f"cluster:{match.group('version')}/{match.group('name')}",
            )
        )
    return tuple(found)


def _discover_databases(
    runner: CommandRunner,
    listeners: tuple[PostgreSQLListener, ...],
    *,
    euid: int | None,
) -> tuple[PostgreSQLDatabaseObservation, ...]:
    uid = os.geteuid() if euid is None and hasattr(os, "geteuid") else euid
    if uid != 0:
        return ()
    inspectable_ports = {
        item.port for item in listeners if item.process == "postgres"
    }
    observations: list[PostgreSQLDatabaseObservation] = []
    for listener in listeners:
        if listener.port not in inspectable_ports:
            observations.append(
                PostgreSQLDatabaseObservation(
                    port=listener.port,
                    name="*",
                    application_tables=None,
                    inspectable=False,
                )
            )
            continue
        names = _list_database_names(runner, listener.port)
        if names is None:
            observations.append(
                PostgreSQLDatabaseObservation(
                    port=listener.port,
                    name="*",
                    application_tables=None,
                    inspectable=False,
                )
            )
            continue
        for name in names:
            tables = _count_application_tables(runner, listener.port, name)
            observations.append(
                PostgreSQLDatabaseObservation(
                    port=listener.port,
                    name=name,
                    application_tables=tables,
                    inspectable=True,
                )
            )
    return tuple(observations)


def _list_database_names(runner: CommandRunner, port: int) -> tuple[str, ...] | None:
    code, output = _psql(
        runner,
        port,
        "postgres",
        "SELECT datname FROM pg_database WHERE NOT datistemplate ORDER BY 1",
    )
    if code != 0:
        return None
    names = tuple(
        line.strip()
        for line in output.splitlines()
        if _SAFE_DB_NAME.fullmatch(line.strip())
    )
    return names


def _count_application_tables(
    runner: CommandRunner, port: int, database: str
) -> int | None:
    code, output = _psql(
        runner,
        port,
        database,
        "SELECT COUNT(*) FROM pg_class AS class "
        "JOIN pg_namespace AS namespace ON namespace.oid = class.relnamespace "
        "WHERE class.relkind = 'r' "
        "AND namespace.nspname NOT IN ('pg_catalog', 'information_schema', 'pg_toast')",
    )
    if code != 0:
        return None
    line = output.strip().splitlines()[0] if output.strip() else ""
    if not line.isdigit():
        return None
    return int(line)


def _psql(runner: CommandRunner, port: int, database: str, sql: str) -> tuple[int, str]:
    if not _SAFE_DB_NAME.fullmatch(database):
        return 1, ""
    return runner(
        [
            "runuser",
            "-u",
            "postgres",
            "--",
            "psql",
            "--no-psqlrc",
            "-At",
            "-p",
            str(port),
            "--dbname",
            database,
            "--command",
            sql,
        ]
    )


def _discover_backups(settings: CoreSettings) -> tuple[int, str, bool]:
    path = settings.backups_dir
    rendered = str(path)
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return 0, rendered, True
    except OSError:
        return 0, rendered, False
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        return 0, rendered, False
    artifacts = 0
    try:
        for child in path.iterdir():
            try:
                child_metadata = child.lstat()
            except OSError:
                return 0, rendered, False
            if stat.S_ISLNK(child_metadata.st_mode):
                return 0, rendered, False
            if stat.S_ISREG(child_metadata.st_mode):
                artifacts += 1
    except OSError:
        return 0, rendered, False
    return artifacts, rendered, True


def _database_detail(item: PostgreSQLDatabaseObservation) -> str:
    if not item.inspectable:
        return (
            f"127.0.0.1:{item.port} not inspected without local postgres credentials"
        )
    if item.application_tables is None:
        return f"127.0.0.1:{item.port} db={item.name} tables=unknown"
    occupancy = "empty" if item.application_tables == 0 else "occupied"
    return (
        f"127.0.0.1:{item.port} db={item.name} "
        f"tables={item.application_tables} ({occupancy})"
    )
