import os

import pytest
from dvc_objects.fs.local import LocalFileSystem

from dvc_data.hashfile.db.local import LocalHashFileDB
from dvc_data.hashfile.hash_info import HashInfo
from dvc_data.hashfile.meta import Meta
from dvc_data.index import DataIndex, DataIndexEntry, ObjectStorage
from dvc_data.index.checkout import apply, compare

localfs = LocalFileSystem()


def test_checkout(tmp_path, odb):
    index = DataIndex(
        {
            ("foo",): DataIndexEntry(
                key=("foo",),
                meta=Meta(),
                hash_info=HashInfo(
                    name="md5", value="d3b07384d113edec49eaa6238ad5ff00"
                ),
            ),
            ("data",): DataIndexEntry(
                key=("data",),
                meta=Meta(isdir=True),
                hash_info=HashInfo(
                    name="md5",
                    value="1f69c66028c35037e8bf67e5bc4ceb6a.dir",
                ),
            ),
        }
    )
    index.storage_map.add_cache(ObjectStorage((), odb))
    diff = compare(None, index)
    apply(diff, str(tmp_path), localfs)
    assert (tmp_path / "foo").read_text() == "foo\n"
    assert (tmp_path / "data").is_dir()
    assert (tmp_path / "data" / "bar").read_text() == "bar\n"
    assert (tmp_path / "data" / "baz").read_text() == "baz\n"
    assert set(tmp_path.iterdir()) == {
        (tmp_path / "foo"),
        (tmp_path / "data"),
    }
    assert set((tmp_path / "data").iterdir()) == {
        (tmp_path / "data" / "bar"),
        (tmp_path / "data" / "baz"),
    }


def test_checkout_file(tmp_path, odb):
    index = DataIndex(
        {
            (): DataIndexEntry(
                key=(),
                meta=Meta(),
                hash_info=HashInfo(
                    name="md5", value="d3b07384d113edec49eaa6238ad5ff00"
                ),
            ),
        }
    )
    index.storage_map.add_cache(ObjectStorage((), odb))
    diff = compare(None, index)
    apply(diff, str(tmp_path / "foo"), localfs)
    assert (tmp_path / "foo").read_text() == "foo\n"


def test_checkout_broken_dir(tmp_path, odb):
    index = DataIndex(
        {
            ("foo",): DataIndexEntry(
                key=("foo",),
                meta=Meta(),
                hash_info=HashInfo(
                    name="md5", value="d3b07384d113edec49eaa6238ad5ff00"
                ),
            ),
            ("data",): DataIndexEntry(
                key=("data",),
                meta=Meta(isdir=True),
                hash_info=HashInfo(
                    name="md5",
                    value="1f69c66028c35037e8bf67e5bc4ceb6a.dir",
                ),
            ),
            ("broken",): DataIndexEntry(
                key=("broken",),
                meta=Meta(isdir=True),
                hash_info=HashInfo(
                    name="md5",
                    value="bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb.dir",
                ),
            ),
        }
    )
    index.storage_map.add_cache(ObjectStorage((), odb))
    diff = compare(None, index)
    apply(diff, str(tmp_path), localfs)
    assert (tmp_path / "foo").read_text() == "foo\n"
    assert (tmp_path / "data").is_dir()
    assert (tmp_path / "data" / "bar").read_text() == "bar\n"
    assert (tmp_path / "data" / "baz").read_text() == "baz\n"
    assert set(tmp_path.iterdir()) == {
        (tmp_path / "foo"),
        (tmp_path / "data"),
    }
    assert set((tmp_path / "data").iterdir()) == {
        (tmp_path / "data" / "bar"),
        (tmp_path / "data" / "baz"),
    }
    assert not (tmp_path / "broken").exists()


def test_checkout_delete_nested_dir(tmp_path, odb):
    old = DataIndex(
        {
            ("dir1",): DataIndexEntry(
                key=("dir1",),
                meta=Meta(isdir=True),
            ),
            ("dir1", "subdir1"): DataIndexEntry(
                key=("dir1", "subdir1"),
                meta=Meta(isdir=True),
            ),
        }
    )
    diff = compare(None, old)
    apply(diff, str(tmp_path), localfs)

    assert (tmp_path / "dir1").exists()
    assert (tmp_path / "dir1").is_dir()
    assert (tmp_path / "dir1" / "subdir1").exists()
    assert (tmp_path / "dir1" / "subdir1").is_dir()

    new = DataIndex({})
    diff = compare(old, new, delete=True)
    apply(diff, str(tmp_path), localfs)

    assert not (tmp_path / "dir1" / "subdir1").exists()
    assert not (tmp_path / "dir1").exists()


FOO_MD5 = "d3b07384d113edec49eaa6238ad5ff00"
BAR_MD5 = "c157a79031e1c40f85931829bc5fc552"


@pytest.fixture
def hardlink_odb(tmp_path_factory):
    path = tmp_path_factory.mktemp("odb")
    odb = LocalHashFileDB(localfs, os.fspath(path), type="hardlink")
    odb.add_bytes(FOO_MD5, b"foo\n")
    odb.add_bytes(BAR_MD5, b"bar\n")
    for oid in (FOO_MD5, BAR_MD5):
        odb.protect(odb.oid_to_path(oid))
    return odb


def _file_index(odb, oid):
    index = DataIndex(
        {
            ("file",): DataIndexEntry(
                key=("file",),
                meta=Meta(),
                hash_info=HashInfo(name="md5", value=oid),
            ),
        }
    )
    index.storage_map.add_cache(ObjectStorage((), odb))
    return index


def test_checkout_relink_keeps_cache_protected(tmp_path, hardlink_odb):
    # https://github.com/treeverse/dvc/issues/11119
    old = _file_index(hardlink_odb, FOO_MD5)
    apply(compare(None, old), str(tmp_path), localfs, links=["hardlink"])
    assert localfs.is_hardlink(str(tmp_path / "file"))

    new = _file_index(hardlink_odb, FOO_MD5)
    apply(compare(old, new, relink=True), str(tmp_path), localfs, links=["hardlink"])

    assert localfs.is_hardlink(str(tmp_path / "file"))
    assert (tmp_path / "file").read_text() == "foo\n"
    assert hardlink_odb.is_protected(hardlink_odb.oid_to_path(FOO_MD5))


def test_checkout_modified_keeps_old_cache_protected(tmp_path, hardlink_odb):
    # https://github.com/treeverse/dvc/issues/11119
    old = _file_index(hardlink_odb, FOO_MD5)
    apply(compare(None, old), str(tmp_path), localfs, links=["hardlink"])

    new = _file_index(hardlink_odb, BAR_MD5)
    apply(compare(old, new), str(tmp_path), localfs, links=["hardlink"])

    assert (tmp_path / "file").read_text() == "bar\n"
    assert hardlink_odb.is_protected(hardlink_odb.oid_to_path(FOO_MD5))
    assert hardlink_odb.is_protected(hardlink_odb.oid_to_path(BAR_MD5))
