# Тесты M-CLI без БД и LLM: разбор аргументов, дефолты, соль из окружения,
# разрешение каталога дампа. (T-012, файл был объявлен планом и не создан)
import os
from pathlib import Path

import pytest

from sanitizer import cli

SUBCOMMANDS = {"demo-seed", "plan", "run", "restore", "verify", "report"}


def parse(argv):
    """Прогон парсера без выполнения: подменяем fn на маркер."""
    import argparse

    parsed = {}
    real = argparse.ArgumentParser.parse_args

    def fake(self, args=None, namespace=None):
        ns = real(self, args, namespace)
        parsed.update(vars(ns))
        return ns

    argparse.ArgumentParser.parse_args = fake
    try:
        ns = None
        try:
            ns = real(_build(), argv)
        except SystemExit:
            raise
        return vars(ns)
    finally:
        argparse.ArgumentParser.parse_args = real


def _build():
    """Собирает тот же парсер, что и main(), не запуская команду."""
    import argparse
    import sys

    argv_backup = sys.argv
    holder = {}
    real_parse = argparse.ArgumentParser.parse_args

    def capture(self, args=None, namespace=None):
        holder["parser"] = self
        raise SystemExit(0)          # прерываем main до выполнения команды

    argparse.ArgumentParser.parse_args = capture
    sys.argv = ["sanitizer"]
    try:
        cli.main()
    except SystemExit:
        pass
    finally:
        argparse.ArgumentParser.parse_args = real_parse
        sys.argv = argv_backup
    return holder["parser"]


def test_all_subcommands_registered():
    parser = _build()
    actions = [a for a in parser._actions if hasattr(a, "choices") and a.choices]
    names = set()
    for a in actions:
        names |= set(a.choices)
    assert SUBCOMMANDS <= names, SUBCOMMANDS - names


def test_every_subcommand_has_handler():
    parser = _build()
    sub = next(a for a in parser._actions if getattr(a, "choices", None) and "plan" in a.choices)
    for name, p in sub.choices.items():
        defaults = p.get_default("fn")
        assert callable(defaults), f"{name}: нет обработчика"


def test_plan_defaults():
    d = parse(["plan"])
    assert d["plan"].endswith("sanitization-plan.yaml")
    assert d["auto_approve"] is False          # гейт по умолчанию включён
    assert "llm_cache" in d


def test_verify_defaults_point_to_both_bases():
    d = parse(["verify"])
    assert "demo" in d["src_dsn"] and "staging" in d["dst_dsn"]
    assert d["canaries"].endswith("canaries.json")


def test_salt_from_environment(monkeypatch):
    monkeypatch.setenv("MASTER_SALT", "test-master")   # умолчания у соли нет намеренно
    monkeypatch.setenv("RECIPIENT", "contractor-x")
    monkeypatch.setenv("GENERATION", "g7")
    monkeypatch.setenv("MASTER_SALT_VERSION", "3")
    s = cli._salt()
    assert (s.recipient, s.generation, s.version) == ("contractor-x", "g7", 3)
    monkeypatch.setenv("RECIPIENT", "other")
    assert cli._salt().effective != s.effective   # разные получатели - разные соли


def test_resolve_dump_picks_latest_timestamp(tmp_path):
    for name in ("1785449108721", "1785450075173", "not-a-dump"):
        (tmp_path / name).mkdir()
    assert cli._resolve_dump(tmp_path).name == "1785450075173"


def test_resolve_dump_accepts_direct_toc(tmp_path):
    (tmp_path / "toc.dat").write_bytes(b"x")
    assert cli._resolve_dump(tmp_path) == tmp_path


def test_resolve_dump_fails_closed(tmp_path):
    with pytest.raises(SystemExit):
        cli._resolve_dump(tmp_path)            # пустой каталог - не молча, а стоп
