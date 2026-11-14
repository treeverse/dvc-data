import os
import sqlite3
from contextlib import closing
from os import fspath
from typing import Any

import pytest

from dvc_data.hashfile.cache import Cache, DiskError, HashesCache, Index


def set_value(cache: Cache, key: str, value: Any) -> Any:
    cache[key] = value
    return cache[key]


def test_values_are_never_pickled(tmp_path):
    """CVE-2025-69872: values are JSON or text, never pickled."""

    class Custom:
        pass

    with Cache(fspath(tmp_path / "test")) as cache, pytest.raises(TypeError):
        cache["key"] = Custom()


def corrupt_every_value(directory: str) -> None:
    # Only once the cache is closed: a second SQLite library on a live database can
    # truncate its shared-memory file under the first one.
    db_path = os.path.join(directory, "sciqlop-cache.db")
    with closing(sqlite3.connect(db_path)) as db:
        db.execute("UPDATE cache SET value = x'c1'")
        db.commit()


@pytest.mark.parametrize("cls", [Cache, Index, HashesCache])
def test_corrupt_entry_raises_disk_error(tmp_path, cls):
    directory = fspath(tmp_path / "test")
    cache = cls(directory)
    cache["key"] = "value"
    cache.close()
    corrupt_every_value(directory)

    cache = cls(directory)
    with pytest.raises(DiskError) as exc:
        cache["key"]
    cache.close()
    assert exc.value.directory == directory
    assert exc.value.type == "test"


def test_reopen(tmp_path):
    with Cache(directory=fspath(tmp_path / "test")) as cache:
        set_value(cache, "key", {"a": [1, "b"]})
    with Cache(directory=fspath(tmp_path / "test"), type="test") as cache:
        assert cache["key"] == {"a": [1, "b"]}
        assert cache._type == "test"


def test_cache_returns_tuples(tmp_path):
    with Cache(fspath(tmp_path / "links")) as cache:
        cache["path"] = (42, "mtime")
        assert cache["path"] == (42, "mtime")
        assert cache.get("path") == (42, "mtime")
        assert cache.get("missing") is None
        assert cache.pop("path") == (42, "mtime")


def test_hashes_cache(tmp_path):
    with HashesCache(tmp_path / "test") as cache:
        assert cache.is_empty()
        cache.set("key", "value")
        assert not cache.is_empty()
        assert cache.get("key") == "value"
        assert cache.get("not-existing-key") is None


def test_hashes_cache_many(tmp_path):
    with HashesCache(tmp_path / "test") as cache:
        assert cache.is_empty()
        assert list(cache.get_many(("key1",))) == [("key1", None)]

        cache.set_many((("key1", "value1"), ("key2", "value2")))
        assert not cache.is_empty()
        assert list(cache.get_many(("key1", "key2"))) == [
            ("key1", "value1"),
            ("key2", "value2"),
        ]
        assert list(cache.get_many(("key1", "key2", "not-existing-key"))) == [
            ("key1", "value1"),
            ("key2", "value2"),
            ("not-existing-key", None),
        ]


@pytest.mark.parametrize("upsert", [True, False])
def test_hashes_cache_update(tmp_path, upsert):
    with HashesCache(tmp_path / "test") as cache:
        cache.SUPPORTS_UPSERT = upsert

        assert cache.is_empty()
        cache.set("key1", "value")
        cache.set_many((("key1", "value1"), ("key2", "value2")))
        assert list(cache.get_many(("key1", "key2"))) == [
            ("key1", "value1"),
            ("key2", "value2"),
        ]
