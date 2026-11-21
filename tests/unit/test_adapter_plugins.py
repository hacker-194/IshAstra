"""Third-party adapters load from `ishastra.adapters` entry points."""

from __future__ import annotations

import importlib.metadata
from types import SimpleNamespace

from ishastra.core import adapters


class _Entry:
    """Minimal stand-in for importlib.metadata.EntryPoint."""

    def __init__(self, name: str, target: object) -> None:
        self.name = name
        self._target = target

    def load(self) -> object:
        return self._target


def _patch(monkeypatch, entries: list[_Entry]) -> None:
    def fake_entry_points(*, group: str):
        assert group == adapters.ADAPTER_PLUGIN_GROUP
        return entries

    monkeypatch.setattr(importlib.metadata, "entry_points", fake_entry_points)


def test_plugin_instance_is_registered(monkeypatch) -> None:
    plugin = SimpleNamespace(id="custom-probe")
    _patch(monkeypatch, [_Entry("custom", plugin)])
    assert adapters._load_plugin_adapters() == {"custom-probe": plugin}


def test_plugin_class_is_instantiated(monkeypatch) -> None:
    class PluginAdapter:
        id = "custom-class"

    _patch(monkeypatch, [_Entry("custom-class", PluginAdapter)])
    loaded = adapters._load_plugin_adapters()
    assert list(loaded) == ["custom-class"]
    assert isinstance(loaded["custom-class"], PluginAdapter)


def test_plugin_cannot_replace_builtin(monkeypatch) -> None:
    _patch(monkeypatch, [_Entry("shadow", SimpleNamespace(id="ishastra-http"))])
    assert adapters._load_plugin_adapters() == {}


def test_broken_plugin_is_ignored(monkeypatch) -> None:
    class Broken:
        name = "broken"

        def load(self):
            raise ImportError("optional dependency missing")

    _patch(monkeypatch, [Broken(), _Entry("no-id", SimpleNamespace())])
    assert adapters._load_plugin_adapters() == {}
