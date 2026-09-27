# Copyright (c) 2026 KeelLinux maintainers
"""Turn measured command output into the Files a database probe reads"""

import sys
from os.path import abspath, dirname

sys.path.insert(0, dirname(dirname(abspath(__file__))))

from keel.inspect.dbengines import ENGINES  # noqa: E402
from keel.inspect.tree import File  # noqa: E402


def answers(engine, answered: dict, problem: str = "") -> dict[str, File]:
    """One File per question, named as the collector names it

    `problem` stands for a server that could not be asked at all: every
    answer carries the reason instead of output, which is what an offline
    root or a stopped service produces.
    """
    built = {}
    for name, argv in engine.questions.items():
        path = " ".join(argv)
        if problem:
            built[name] = File(path, problem=problem)
        else:
            built[name] = File(path, answered.get(name, ""))
    return built


def _reading(name: str, answered: dict, sockets: str, problem: str = ""):
    engine = next(one for one in ENGINES if one.name == name)
    return engine.read(
        answers(engine, answered, problem), File("ss -lntH", sockets)
    )


def mariadb_reading(answered: dict, sockets: str, problem: str = ""):
    return _reading("mariadb", answered, sockets, problem)


def postgresql_reading(answered: dict, sockets: str, problem: str = ""):
    return _reading("postgresql", answered, sockets, problem)


def redis_reading(answered: dict, sockets: str, problem: str = ""):
    return _reading("redis", answered, sockets, problem)
