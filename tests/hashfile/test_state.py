import os
from contextlib import closing

import pytest
from dvc_objects.fs import MemoryFileSystem
from dvc_objects.fs.local import LocalFileSystem
from dvc_objects.fs.system import inode

from dvc_data.hashfile.hash import file_md5
from dvc_data.hashfile.hash_info import HashInfo
from dvc_data.hashfile.meta import Meta
from dvc_data.hashfile.state import State, StateNoop, _checksum
from dvc_data.hashfile.utils import get_mtime_and_size
from dvc_data.json_compat import dumps as json_dumps


@pytest.fixture
def state(tmp_path):
    with closing(State(tmp_path, tmp_path / "tmp")) as _state:
        yield _state


def test_hashes(tmp_path, state: State):
    path = tmp_path / "foo"
    path.write_text("foo content", encoding="utf-8")

    fs = LocalFileSystem()
    hash_info = HashInfo(name="md5", value="6dbda444875c24ec1bbdb433456be11f")

    state.save(str(path), fs, hash_info)
    info = fs.info(str(path))
    meta = Meta.from_info(info)
    assert state.hashes[str(path)] == json_dumps(
        {
            "version": 1,
            "checksum": _checksum(info),
            "size": 11,
            "hash_info": {"md5": hash_info.value},
        }
    )
    assert state.get(str(path), fs) == (meta, hash_info)
    assert list(state.get_many((str(path),), fs, {})) == [(str(path), meta, hash_info)]

    path.write_text("foo content 1", encoding="utf-8")
    info = fs.info(str(path))
    meta = Meta.from_info(info)
    hash_info = HashInfo(name="md5", value="8efcb74434c93f295375a9118292fd0c")
    path.unlink()

    state.save(str(path), fs, hash_info, info)
    assert state.hashes[str(path)] == json_dumps(
        {
            "version": 1,
            "checksum": _checksum(info),
            "size": 13,
            "hash_info": {"md5": hash_info.value},
        }
    )
    assert state.get(str(path), fs, info) == (meta, hash_info)
    assert list(state.get_many((str(path),), fs, {str(path): info})) == [
        (str(path), meta, hash_info)
    ]

    assert state.get(str(path), fs) == (None, None)
    assert list(state.get_many((str(path),), fs, {})) == [(str(path), None, None)]


def test_hashes_get_not_a_local_fs(tmp_path, state: State):
    fs = MemoryFileSystem()

    assert state.get("not-existing-file", fs) == (None, None)
    assert list(state.get_many(("not-existing-file",), fs, {})) == [
        ("not-existing-file", None, None)
    ]


def test_hashes_get_invalid_data(tmp_path, state: State):
    path = tmp_path / "foo"
    path.write_text("foo content", encoding="utf-8")

    fs = LocalFileSystem()

    # invalid json
    state.hashes[str(path)] = ""
    assert state.get(str(path), fs) == (None, None)
    assert list(state.get_many((str(path),), fs, {})) == [(str(path), None, None)]

    # invalid json
    state.hashes[str(path)] = '{"x"}'
    assert state.get(str(path), fs) == (None, None)
    assert list(state.get_many((str(path),), fs, {})) == [(str(path), None, None)]

    # invalid checksum
    state.hashes[str(path)] = json_dumps(
        {
            "version": 1,
            "checksum": 1,
            "size": 13,
            "hash_info": {"md5": "value"},
        }
    )
    assert state.get(str(path), fs) == (None, None)
    assert list(state.get_many((str(path),), fs, {})) == [(str(path), None, None)]

    # invalid version
    state.hashes[str(path)] = json_dumps(
        {
            "version": state.HASH_VERSION + 1,
            "checksum": _checksum(fs.info(str(path))),
            "size": 13,
            "hash_info": {"md5": "value"},
        }
    )
    assert state.get(str(path), fs) == (None, None)
    assert list(state.get_many((str(path),), fs, {})) == [(str(path), None, None)]


def test_hashes_without_version(tmp_path, state: State):
    # If there is no version, it is considered as old md5-dos2unix hashes.
    # dvc-data does not write this format anymore, but it should be able to read it
    fs = LocalFileSystem()

    path = tmp_path / "foo"
    path.write_text("foo content", encoding="utf-8")

    info = fs.info(str(path))
    meta = Meta.from_info(info)

    state.hashes[str(path)] = json_dumps(
        {
            "checksum": _checksum(info),
            "size": 11,
            "hash_info": {"md5": "value"},
        }
    )
    assert state.get(str(path), fs) == (
        meta,
        HashInfo("md5-dos2unix", "value"),
    )
    assert list(state.get_many((str(path),), fs, {})) == [
        (str(path), meta, HashInfo("md5-dos2unix", "value"))
    ]


def test_hashes_save_not_existing(tmp_path, state: State):
    fs = LocalFileSystem()

    with pytest.raises(FileNotFoundError):
        state.save("not-existing-file", fs, HashInfo("md5", "value"))

    state.save_many((("not-existing-file", HashInfo("md5", "value"), None),), fs)
    assert len(state.hashes) == 0


def test_hashes_save_when_fs_is_not_a_local_fs(tmp_path, state: State):
    fs = MemoryFileSystem()

    state.save("not-existing-file", fs, HashInfo("md5", "value"))
    assert len(state.hashes) == 0

    state.save_many((("not-existing-file", HashInfo("md5", "value"), None),), fs)
    assert len(state.hashes) == 0


def test_state_many(tmp_path, state: State):
    foo = tmp_path / "foo"
    foo.write_text("foo content", encoding="utf-8")

    bar = tmp_path / "bar"
    bar.write_text("bar content", encoding="utf-8")

    fs = LocalFileSystem()

    hash_info_foo = HashInfo("md5", file_md5(foo, fs))
    foo_info = fs.info(str(foo))
    bar_info = fs.info(str(bar))
    hash_info_bar = HashInfo("md5", file_md5(bar, fs))

    state.save_many(
        [(str(foo), hash_info_foo, None), (str(bar), hash_info_bar, None)], fs
    )
    assert list(state.get_many([str(foo), str(bar)], fs, {})) == [
        (str(foo), Meta.from_info(foo_info), hash_info_foo),
        (str(bar), Meta.from_info(bar_info), hash_info_bar),
    ]

    foo.write_text("foo content 1", encoding="utf-8")
    foo_info = fs.info(str(foo))
    hash_info_foo = HashInfo("md5", file_md5(foo, fs))
    foo.unlink()
    bar.write_text("bar content 1", encoding="utf-8")
    bar_info = fs.info(str(bar))
    hash_info_bar = HashInfo("md5", file_md5(bar, fs))
    bar.unlink()

    state.save_many(
        [(str(foo), hash_info_foo, foo_info), (str(bar), hash_info_bar, bar_info)], fs
    )
    assert list(
        state.get_many(
            [str(foo), str(bar)], fs, {str(foo): foo_info, str(bar): bar_info}
        )
    ) == [
        (str(foo), Meta.from_info(foo_info), hash_info_foo),
        (str(bar), Meta.from_info(bar_info), hash_info_bar),
    ]


def test_set_link(tmp_path, state):
    state.set_link(tmp_path / "foo", 42, "mtime")
    # The link cache serializes as JSON, which has no tuple type, so the pair
    # reads back as a list. `get_unused_links` compares it as a sequence.
    assert tuple(state.links["foo"]) == (42, "mtime")


def test_state_noop(tmp_path):
    state = StateNoop()
    fs = LocalFileSystem()

    state.save_many([("foo", HashInfo("md5", "value"), None)], fs)
    assert state.get("foo", fs) == (None, None)
    assert list(state.get_many(("foo", "bar"), fs, {})) == [
        ("foo", None, None),
        ("bar", None, None),
    ]

    state.set_link(tmp_path / "foo", 42, "mtime")
    assert state.get_unused_links([], fs) == []

    state.save_link(tmp_path / "foo", fs)
    assert state.get_unused_links([], fs) == []


def test_links(tmp_path, state: State):
    foo, bar = tmp_path / "foo", tmp_path / "bar"
    dataset = tmp_path / "dataset"
    dataset.mkdir()
    file = dataset / "file"

    for path in [foo, bar, file]:
        path.write_text(f"{path.name} content", encoding="utf-8")

    fs = LocalFileSystem()

    state.save_link(os.fspath(foo), fs)
    state.save_link(os.fspath(bar), fs)
    state.save_link(os.fspath(dataset), fs)

    def _get_inode_mtime(path):
        path = os.fspath(path)
        return inode(path), get_mtime_and_size(path, fs)[0]

    assert len(state.links) == 3
    # Values come back as lists: the link cache serializes as JSON, which has
    # no tuple type.
    assert {k: tuple(state.links[k]) for k in state.links} == {
        "foo": _get_inode_mtime(foo),
        "bar": _get_inode_mtime(bar),
        "dataset": _get_inode_mtime(dataset),
    }

    links = [os.fspath(tmp_path / link) for link in ["foo", "bar", "dataset"]]
    assert set(state.get_unused_links([], fs)) == {"foo", "bar", "dataset"}
    assert set(state.get_unused_links(links[:1], fs)) == {"bar", "dataset"}
    assert set(state.get_unused_links(links[:2], fs)) == {"dataset"}
    assert set(state.get_unused_links(links, fs)) == set()
    assert set(
        state.get_unused_links(
            ([*links[:1], os.path.join(tmp_path, "not-existing-file")]),
            fs,
        )
    ) == {"bar", "dataset"}

    state.remove_links(["foo", "bar", "dataset"], fs)
    assert len(state.links) == 0
    assert not foo.exists()
    assert not bar.exists()
    assert not dataset.exists()


def test_legacy_pickled_links_are_dropped(tmp_path):
    """A links cache written by an older dvc-data is discarded, not unpickled.

    `get_unused_links` iterates the cache, and reading a legacy entry evicts
    it, so the loop must tolerate the mutation rather than raising KeyError.
    """
    import diskcache

    from dvc_data.hashfile.cache import Disk

    tmp = tmp_path / "tmp"
    links_dir = tmp / "links"
    links_dir.mkdir(parents=True)

    foo = tmp_path / "foo"
    foo.write_text("foo content", encoding="utf-8")

    with diskcache.Cache(str(links_dir), disk=Disk, disk_pickle_protocol=4) as cache:
        cache.disk._type = cache._type = "links"
        cache["foo"] = (inode(os.fspath(foo)), "mtime")

    fs = LocalFileSystem()
    state = State(root_dir=os.fspath(tmp_path), tmp_dir=os.fspath(tmp))
    try:
        assert state.get_unused_links([], fs) == []

        # Re-recording the link works, and is stored without pickle.
        state.save_link(os.fspath(foo), fs)
        assert set(state.get_unused_links([], fs)) == {"foo"}
    finally:
        state.close()
