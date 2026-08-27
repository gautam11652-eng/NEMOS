"""Regression tests for the renamed NEMOS package namespace."""

import importlib


def test_nemos_package_imports():
    package = importlib.import_module("nemos")
    assert package.__name__ == "nemos"


def test_core_nemos_modules_import():
    modules = (
        "nemos.models",
        "nemos.config",
        "nemos.database",
        "nemos.storage",
        "nemos.detector",
        "nemos.behavioral",
        "nemos.intelligence",
        "nemos.capture",
        "nemos.api",
    )
    for name in modules:
        assert importlib.import_module(name).__name__ == name
