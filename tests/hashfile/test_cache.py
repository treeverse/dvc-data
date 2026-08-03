import json
import os
import pathlib
import pickle
import sqlite3
from contextlib import closing
from os import fspath
from typing import Any

import diskcache
import pytest
from diskcache.core import MODE_PICKLE

from dvc_data.hashfile.cache import Cache, Disk, DiskError, HashesCache


def set_value(cache: Cache, key: str, value: Any) -> Any:
    cache[key] = value
    return cache[key]


def pickled_rows(cache: diskcache.Cache) -> list[str]:
    """Keys whose stored value is a pickle stream.

    Protocol 2+ pickles start with the PROTO opcode (0x80), which no JSON
    encoding can begin with.
    """
    rows = cache._sql("SELECT key, value FROM Cache").fetchall()
    return sorted(
        key
        for key, value in rows
        if isinstance(value, (bytes, memoryview)) and bytes(value)[:1] == b"\x80"
    )


@pytest.mark.parametrize("disk_type", [None, "test"])
def test_pickle_protocol_error(tmp_path, disk_type):
    """An unusable pickle protocol is still reported as a DiskError.

    Keys are pickled by the base class, so this path stays live even though
    values are now serialized as JSON.
    """
    directory = tmp_path / "test"
    cache = Cache(
        fspath(directory),
        disk_pickle_protocol=pickle.HIGHEST_PROTOCOL + 1,
        type=disk_type,
    )
    with pytest.raises(DiskError) as exc, cache as cache:
        set_value(cache, ("tuple", "key"), "value")
    assert exc.value.directory == fspath(directory)
    assert exc.value.type == "test"
    assert f"Could not open disk 'test' in {directory}" == str(exc.value)


@pytest.mark.parametrize("disk_type", [None, "test"])
def test_pickle_protocol_does_not_affect_values(tmp_path, disk_type):
    """Values no longer depend on the pickle protocol being usable."""
    with Cache(
        fspath(tmp_path / "test"),
        disk_pickle_protocol=pickle.HIGHEST_PROTOCOL + 1,
        type=disk_type,
    ) as cache:
        assert set_value(cache, "key", {"loaded": True}) == {"loaded": True}


@pytest.mark.parametrize(
    "proto_a, proto_b",
    [
        (pickle.HIGHEST_PROTOCOL - 1, pickle.HIGHEST_PROTOCOL),
        (pickle.HIGHEST_PROTOCOL, pickle.HIGHEST_PROTOCOL - 1),
    ],
)
def test_readable_across_pickle_protocols(tmp_path, proto_a, proto_b):
    """A cache stays readable across `disk_pickle_protocol` settings.

    Values are serialized as JSON, so the pickle protocol no longer applies to
    them at all -- which is what makes them readable either way. Tuples come
    back as lists because JSON has no tuple type.
    """
    with Cache(
        directory=fspath(tmp_path / "test"),
        disk_pickle_protocol=proto_a,
    ) as cache:
        set_value(cache, "key", ("value1", "value2"))
    with Cache(
        directory=fspath(tmp_path / "test"),
        disk_pickle_protocol=proto_b,
    ) as cache:
        assert cache["key"] == ["value1", "value2"]
        assert set_value(cache, "key", ("value3", "value4")) == ["value3", "value4"]


def test_hashes_cache(tmp_path):
    with HashesCache(tmp_path / "test") as cache:
        assert cache.is_empty()
        assert cache.set("key", "value")
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


# The values dvc-data actually caches, per its four Cache/Index call sites:
# hashfile/state.py (links), hashfile/db/index.py (ODB index), index/serialize.py.
DVC_CACHED_VALUES = [
    pytest.param((12345, 1699999999.5), id="links-inode-mtime"),
    pytest.param(True, id="index-is-dir"),
    pytest.param(False, id="index-is-file"),
    pytest.param(
        {
            "meta": {"size": 3, "isexec": True},
            "hash_info": {"md5": "x"},
            "loaded": True,
        },
        id="index-entry-dict",
    ),
    pytest.param({"loaded": False}, id="index-entry-minimal"),
    pytest.param('{"version":1,"checksum":"a","size":12}', id="hashes-json-string"),
]


@pytest.mark.parametrize("value", DVC_CACHED_VALUES)
def test_values_are_not_pickled(tmp_path, value):
    """No value dvc-data caches may be written as a pickle.

    diskcache unpickles on read, so a pickled value makes the cache directory a
    code-execution surface for anything that can write into it
    (CVE-2025-69872, unfixed upstream). Guards against a regression back to
    pickle serialization.
    """
    with Cache(fspath(tmp_path / "test")) as cache:
        cache["key"] = value
        assert pickled_rows(cache) == []


@pytest.mark.parametrize("value", DVC_CACHED_VALUES)
def test_values_round_trip(tmp_path, value):
    """JSON serialization must preserve every value shape dvc-data stores.

    Tuples come back as lists -- JSON has no tuple type -- so compare
    structurally. `state.get_unused_links` accounts for this explicitly.
    """
    with Cache(fspath(tmp_path / "test")) as cache:
        cache["key"] = value
        got = cache["key"]

    if isinstance(value, tuple):
        assert tuple(got) == value
    else:
        assert got == value


def test_stored_value_is_json(tmp_path):
    with Cache(fspath(tmp_path / "test")) as cache:
        cache["key"] = {"loaded": True, "meta": {"size": 3}}
        ((raw,),) = cache._sql("SELECT value FROM Cache").fetchall()
        assert json.loads(bytes(raw)) == {"loaded": True, "meta": {"size": 3}}


def _write_legacy_pickled_entries(directory: str) -> None:
    """Write entries the way a pre-JSON dvc-data did, via the pickling Disk."""
    with diskcache.Cache(directory, disk=Disk, disk_pickle_protocol=4) as cache:
        cache.disk._type = cache._type = "test"
        cache["tuple"] = (1, 2.5)
        cache["bool"] = True


def test_legacy_pickled_entry_is_a_miss(tmp_path):
    """A cache written by an older dvc-data must not be unpickled.

    These caches live under `tmp_dir` and are regenerable, so a legacy entry
    degrades to a miss (and is evicted) rather than raising or executing.
    """
    directory = fspath(tmp_path / "test")
    _write_legacy_pickled_entries(directory)

    with Cache(directory) as cache:
        assert pickled_rows(cache) == ["bool", "tuple"]

        assert cache.get("tuple", "MISS") == "MISS"
        assert cache.get("bool", "MISS") == "MISS"

        # Reads evict the poisoned rows, so nothing pickled survives.
        assert pickled_rows(cache) == []


def test_legacy_pickled_entry_raises_key_error(tmp_path):
    directory = fspath(tmp_path / "test")
    _write_legacy_pickled_entries(directory)

    with Cache(directory) as cache:
        with pytest.raises(KeyError):
            cache["tuple"]
        assert "tuple" not in cache


def test_legacy_entry_is_replaced_on_write(tmp_path):
    directory = fspath(tmp_path / "test")
    _write_legacy_pickled_entries(directory)

    with Cache(directory) as cache:
        cache["tuple"] = (3, 4.5)
        assert tuple(cache["tuple"]) == (3, 4.5)
        assert pickled_rows(cache) == ["bool"]


def test_hashes_cache_is_unaffected(tmp_path):
    """HashesCache reads and writes via raw SQL, bypassing the disk layer."""
    with HashesCache(fspath(tmp_path / "test")) as cache:
        cache.set("key", '{"version":1}')
        cache.set_many((("k2", '{"version":2}'),))
        assert cache.get("key") == '{"version":1}'
        assert list(cache.get_many(("k2",))) == [("k2", '{"version":2}')]
        assert pickled_rows(cache) == []


def test_poisoned_entry_is_not_executed(tmp_path):
    """A payload injected into the cache directory must not be unpickled.

    This is the CVE-2025-69872 attack: an attacker who can write to the cache
    directory replaces a value with a pickle whose `__reduce__` runs a command,
    and the next process to read that key executes it. Against stock diskcache
    this succeeds; the JSON disk refuses the entry instead.
    """
    marker = tmp_path / "executed"

    class Evil:
        def __reduce__(self):
            return (pathlib.Path.touch, (marker,))

    directory = fspath(tmp_path / "test")
    with Cache(directory) as cache:
        cache["key"] = {"placeholder": True}

    # Overwrite the stored value with a pickle payload, as an attacker with
    # write access to the cache directory could.
    con = sqlite3.connect(os.path.join(directory, "cache.db"))
    with closing(con):
        con.execute(
            "UPDATE Cache SET mode = ?, value = ?, filename = NULL WHERE key = 'key'",
            (MODE_PICKLE, sqlite3.Binary(pickle.dumps(Evil(), protocol=4))),
        )
        con.commit()

    with Cache(directory) as cache:
        assert cache.get("key", "MISS") == "MISS"

    assert not marker.exists(), "the poisoned payload was executed"
