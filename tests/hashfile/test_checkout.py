import os
from copy import deepcopy
from functools import partial
from os.path import realpath, samefile
from pathlib import Path

import pytest
from attrs import evolve
from dvc_objects.fs.generic import transfer
from dvc_objects.fs.local import LocalFileSystem, localfs
from dvc_objects.fs.system import inode

from dvc_data.hashfile import checkout as checkout_mod
from dvc_data.hashfile.build import build
from dvc_data.hashfile.checkout import LinkError, _determine_files_to_relink, checkout
from dvc_data.hashfile.db import HashFileDB
from dvc_data.hashfile.db.local import LocalHashFileDB
from dvc_data.hashfile.diff import Change, DiffResult, TreeEntry
from dvc_data.hashfile.state import State
from dvc_data.hashfile.transfer import transfer as otransfer
from dvc_data.hashfile.utils import get_mtime_and_size


@pytest.mark.parametrize("cache_type", ["copy", "hardlink", "symlink", "reflink"])
@pytest.mark.parametrize("link", ["copy", "hardlink", "symlink", "reflink"])
def test_determine_relinking(tmp_path, cache_type, link):
    fs = LocalFileSystem()
    cache = HashFileDB(fs, tmp_path, type=[cache_type])

    foo_oid = "acbd18db4cc2f85cedef654fccc4a4d8"
    cache.add_bytes(foo_oid, b"foo")
    bar_oid = "37b51d194a7513e45b56f6524f2d51f2"
    cache.add_bytes(bar_oid, b"bar")

    try:
        transfer(
            fs,
            [cache.oid_to_path(foo_oid), cache.oid_to_path(bar_oid)],
            fs,
            [tmp_path / "foo", tmp_path / "bar"],
            links=[link],
        )
    except OSError:
        if link == "reflink":
            pytest.skip(f"{link=} not supported")

    _, foo_meta, foo_obj = build(cache, str(tmp_path / "foo"), fs, "md5")
    _, bar_meta, bar_obj = build(cache, str(tmp_path / "bar"), fs, "md5")
    foo_entry = TreeEntry(cache.check(foo_oid), ("foo",), foo_meta, foo_obj.hash_info)
    bar_entry = TreeEntry(cache.check(bar_oid), ("bar",), bar_meta, bar_obj.hash_info)
    diff = DiffResult(
        unchanged=[Change(foo_entry, foo_entry), Change(bar_entry, bar_entry)]
    )

    # _determine_files_to_relink modifies existing diff
    old_diff = deepcopy(diff)
    _determine_files_to_relink(diff, "dataset", fs, cache)

    if cache_type == link or {cache_type, link} <= {"copy", "reflink"}:
        assert diff == old_diff
    else:
        assert diff == evolve(old_diff, modified=old_diff.unchanged)


def _check_link(path, target, link_type):
    if link_type in ("reflink", "copy"):
        return (
            localfs.iscopy(path)
            and Path(path).read_bytes() == Path(target).read_bytes()
        )
    if link_type == "symlink":
        return realpath(path) == target
    if link_type == "hardlink":
        return samefile(path, target)
    raise ValueError(f"Unknown {link_type=}")


@pytest.mark.parametrize("link", ["copy", "hardlink", "symlink", "reflink"])
@pytest.mark.parametrize("cache_type", ["copy", "hardlink", "symlink", "reflink"])
@pytest.mark.parametrize("db_cls", [HashFileDB, LocalHashFileDB])
def test_checkout_relinking(tmp_path, cache_type, link, db_cls):
    fs = LocalFileSystem()
    cache = db_cls(fs, tmp_path, type=[cache_type])

    foo_oid = "acbd18db4cc2f85cedef654fccc4a4d8"
    cache.add_bytes(foo_oid, b"foo")
    bar_oid = "37b51d194a7513e45b56f6524f2d51f2"
    cache.add_bytes(bar_oid, b"bar")

    (tmp_path / "dataset").mkdir()
    try:
        transfer(
            fs,
            [cache.oid_to_path(foo_oid), cache.oid_to_path(bar_oid)],
            fs,
            [tmp_path / "dataset" / "foo", tmp_path / "dataset" / "bar"],
            links=[link],
        )
    except OSError:
        if link == "reflink":
            pytest.skip(f"{link=} not supported")

    _, _, obj = build(cache, str(tmp_path / "dataset"), fs, "md5")
    assert obj.hash_info.value == "5ea40360f5b4ec688df672a4db9c17d1.dir"

    try:
        checkout(str(tmp_path / "dataset"), fs, obj, cache, relink=True)
    except LinkError:
        if cache_type == "reflink":
            pytest.skip(f"{cache_type=} not supported for checkout")

    assert _check_link(
        tmp_path / "dataset" / "foo", cache.oid_to_path(foo_oid), cache_type
    )
    assert _check_link(
        tmp_path / "dataset" / "bar", cache.oid_to_path(bar_oid), cache_type
    )

    expected = cache_type not in ("copy", "reflink") and isinstance(
        cache, LocalHashFileDB
    )
    assert cache.is_protected(str(tmp_path / "dataset" / "foo")) == expected
    assert cache.is_protected(str(tmp_path / "dataset" / "bar")) == expected


@pytest.mark.parametrize("link", ["copy", "hardlink", "symlink", "reflink"])
@pytest.mark.parametrize("cache_type", ["copy", "hardlink", "symlink", "reflink"])
@pytest.mark.parametrize("db_cls", [HashFileDB, LocalHashFileDB])
def test_checkout_relinking_optimization(mocker, tmp_path, cache_type, link, db_cls):
    fs = LocalFileSystem()
    cache = db_cls(fs, tmp_path, type=[cache_type])

    foo_oid = "acbd18db4cc2f85cedef654fccc4a4d8"
    cache.add_bytes(foo_oid, b"foo")
    bar_oid = "37b51d194a7513e45b56f6524f2d51f2"
    cache.add_bytes(bar_oid, b"bar")

    (tmp_path / "dataset").mkdir()
    fs.pipe(str(tmp_path / "dataset" / "foo"), b"foo")

    try:
        transfer(
            fs,
            [cache.oid_to_path(bar_oid)],
            fs,
            [tmp_path / "dataset" / "bar"],
            links=[link],
        )
    except OSError:
        if link == "reflink":
            pytest.skip(f"{link=} not supported")

    _, _, obj = build(cache, str(tmp_path / "dataset"), fs, "md5")
    assert obj.hash_info.value == "5ea40360f5b4ec688df672a4db9c17d1.dir"
    m = mocker.spy(checkout_mod, "_checkout_file")

    try:
        checkout(str(tmp_path / "dataset"), fs, obj, cache, relink=True)
    except LinkError:
        if cache_type == "reflink":
            pytest.skip(f"{cache_type=} not supported for checkout")

    ca = m.call_args_list

    if {cache_type, link} <= {"copy", "reflink"}:
        assert m.call_count == 0
    elif cache_type in (link, "copy", "reflink"):
        changed_file = "foo" if cache_type == link else "bar"
        assert m.call_count == 1
        assert ca[0][0][1] == str(tmp_path / "dataset" / changed_file)
    else:
        assert m.call_count == 2
        assert {ca[0][0][1], ca[1][0][1]} == {
            str(tmp_path / "dataset" / "foo"),
            str(tmp_path / "dataset" / "bar"),
        }

    assert _check_link(
        tmp_path / "dataset" / "foo", cache.oid_to_path(foo_oid), cache_type
    )
    assert _check_link(
        tmp_path / "dataset" / "bar", cache.oid_to_path(bar_oid), cache_type
    )

    expected = cache_type not in ("copy", "reflink") and isinstance(
        cache, LocalHashFileDB
    )
    assert cache.is_protected(str(tmp_path / "dataset" / "foo")) == expected
    assert cache.is_protected(str(tmp_path / "dataset" / "bar")) == expected


@pytest.mark.parametrize("relink", [True, False])
def test_recheckout_old_obj(tmp_path, relink):
    fs = LocalFileSystem()
    cache = HashFileDB(fs, str(tmp_path))

    fs.makedirs(tmp_path / "dir" / "sub")
    fs.pipe(
        {
            str(tmp_path / "dir" / "foo"): b"foo",
            str(tmp_path / "dir" / "bar"): b"bar",
            str(tmp_path / "dir" / "sub" / "file"): b"file",
        }
    )
    staging, _, obj = build(cache, str(tmp_path / "dir"), fs, "md5")
    otransfer(staging, cache, {obj.hash_info}, shallow=False)

    (tmp_path / "dir" / "sub" / "file").unlink()
    fs.pipe(
        {str(tmp_path / "dir" / "foo"): b"food", str(tmp_path / "dir" / "bar"): b"baz"}
    )

    checkout(str(tmp_path / "dir"), fs, obj, cache, force=True, relink=relink)

    assert (tmp_path / "dir" / "foo").read_text() == "foo"
    assert (tmp_path / "dir" / "bar").read_text() == "bar"


def get_inode_and_mtime(path):
    # A list, not a tuple: the link cache serializes as JSON, which has no
    # tuple type, so `state.links[...]` reads back as a list.
    return [inode(path), get_mtime_and_size(os.fspath(path), localfs)[0]]


def test_checkout_save_link_dir(request, tmp_path):
    fs = LocalFileSystem()
    state = State(tmp_path, tmp_dir=tmp_path / "tmp")
    request.addfinalizer(state.close)

    cache = HashFileDB(fs, str(tmp_path), state=state)

    directory = tmp_path / "dir"
    directory.mkdir()
    (directory / "foo").write_text("foo", encoding="utf-8")
    (directory / "bar").write_text("bar", encoding="utf-8")

    staging, _, obj = build(cache, os.fspath(directory), fs, "md5")
    otransfer(staging, cache, {obj.hash_info}, shallow=False)
    chkout = partial(checkout, os.fspath(directory), fs, obj, cache=cache, state=state)

    chkout()
    assert "dir" not in state.links

    chkout(relink=True)
    assert state.links["dir"] == get_inode_and_mtime(directory)

    # modify file
    (directory / "foo").write_text("food", encoding="utf-8")
    chkout(force=True)
    assert state.links["dir"] == get_inode_and_mtime(directory)

    # remove file
    (directory / "bar").unlink()
    chkout()
    assert state.links["dir"] == get_inode_and_mtime(directory)

    # add file
    (directory / "foobar").write_text("foobar", encoding="utf-8")
    chkout(force=True)
    assert state.links["dir"] == get_inode_and_mtime(directory)


def test_checkout_save_link_file(request, tmp_path):
    fs = LocalFileSystem()
    state = State(tmp_path, tmp_dir=tmp_path / "tmp")
    request.addfinalizer(state.close)

    cache = HashFileDB(fs, os.fspath(tmp_path), state=state)

    file = tmp_path / "foo"
    file.write_text("foo", encoding="utf-8")

    staging, _, obj = build(cache, os.fspath(file), fs, "md5")
    otransfer(staging, cache, {obj.hash_info}, shallow=False)
    chkout = partial(checkout, os.fspath(file), fs, obj, cache=cache, state=state)

    chkout()
    assert "foo" not in state.links

    chkout(relink=True)
    assert state.links["foo"] == get_inode_and_mtime(file)

    # modify file
    file.write_text("food", encoding="utf-8")
    chkout(force=True)
    assert state.links["foo"] == get_inode_and_mtime(file)

    # remove file
    file.unlink()
    chkout()
    assert state.links["foo"] == get_inode_and_mtime(file)
