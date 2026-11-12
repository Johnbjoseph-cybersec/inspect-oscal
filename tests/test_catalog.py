from __future__ import annotations

import hashlib
from importlib import resources

import pytest

from inspect_oscal import catalog as cat
from inspect_oscal.constants import AI_RMF_CATALOG_SHA256


def test_vendored_catalog_hash_equals_constant() -> None:
    assert hashlib.sha256(cat.catalog_bytes()).hexdigest() == AI_RMF_CATALOG_SHA256


def test_catalog_contents() -> None:
    c = cat.load_catalog()
    assert len(c.control_ids) == 91
    assert c.has_control("MEASURE_2.7")
    assert not c.has_control("NOPE_9.9")
    assert c.overview_part("MEASURE_2.7") == "MEASURE_2.7_ovw"
    assert c.overview_part("NOPE_9.9") is None


def test_licence_recorded() -> None:
    data = resources.files("inspect_oscal.data")
    text = data.joinpath("NIST_LICENSE.md").read_text("utf-8")
    assert "public domain" in text and "CC0" in text
    assert "09de09ec" in data.joinpath("SOURCE.md").read_text("utf-8")
    assert "NIST_AI-RMF_v1_catalog.json" in data.joinpath("SHA256SUMS").read_text("utf-8")


def test_tampered_catalog_is_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    cat.load_catalog.cache_clear()
    monkeypatch.setattr(cat, "catalog_bytes", lambda: b"{}")
    with pytest.raises(cat.CatalogError):
        cat.load_catalog()
    monkeypatch.undo()
    cat.load_catalog.cache_clear()
    assert cat.verify_catalog() == AI_RMF_CATALOG_SHA256
