import json
from operator import itemgetter

import pytest
from dvc_objects.errors import ObjectFormatError
from dvc_objects.fs.local import LocalFileSystem

from dvc_data.hashfile.db import HashFileDB
from dvc_data.hashfile.hash_info import HashInfo
from dvc_data.hashfile.meta import Meta
from dvc_data.hashfile.tree import MergeError, Tree, _merge, _try_load


@pytest.mark.parametrize(
    "entries",
    [[None], [{}], [{"relpath": 42}], [{"relpath": "file", "md5": "a", "sha256": "b"}]],
)
def test_load_malformed_tree_entries_reports_corruption(tmp_path, entries):
    odb = HashFileDB(LocalFileSystem(), str(tmp_path / "cache"))
    info = HashInfo("md5", "abcd.dir")
    assert info.value is not None
    odb.add_bytes(info.value, json.dumps(entries).encode())

    with pytest.raises(ObjectFormatError, match="corrupted"):
        Tree.load(odb, info)


def test_try_load_falls_back_after_malformed_tree_entries(tmp_path):
    fs = LocalFileSystem()
    first = HashFileDB(fs, str(tmp_path / "first"))
    second = HashFileDB(fs, str(tmp_path / "second"))
    info = HashInfo("md5", "abcd.dir")
    assert info.value is not None
    first.add_bytes(info.value, b"[{}]")
    second.add_bytes(info.value, b'[{"relpath":"file","md5":"abc"}]')

    loaded = _try_load([first, second], info)

    assert isinstance(loaded, Tree)
    entry = loaded.get(("file",))
    assert entry is not None
    assert entry[1] == HashInfo("md5", "abc")


@pytest.mark.parametrize(
    "lst, trie_dict",
    [
        ([], {}),
        (
            [
                {"md5": "def", "relpath": "zzz"},
                {"md5": "123", "relpath": "foo"},
                {"md5": "abc", "relpath": "aaa"},
                {"md5": "456", "relpath": "bar"},
            ],
            {
                ("zzz",): (Meta(md5="def"), HashInfo("md5", "def")),
                ("foo",): (Meta(md5="123"), HashInfo("md5", "123")),
                ("bar",): (Meta(md5="456"), HashInfo("md5", "456")),
                ("aaa",): (Meta(md5="abc"), HashInfo("md5", "abc")),
            },
        ),
        (
            [
                {"md5": "123", "relpath": "dir/b"},
                {"md5": "456", "relpath": "dir/z"},
                {"md5": "789", "relpath": "dir/a"},
                {"md5": "abc", "relpath": "b"},
                {"md5": "def", "relpath": "a"},
                {"md5": "ghi", "relpath": "z"},
                {"md5": "jkl", "relpath": "dir/subdir/b"},
                {"md5": "mno", "relpath": "dir/subdir/z"},
                {"md5": "pqr", "relpath": "dir/subdir/a"},
            ],
            {
                ("dir", "b"): (
                    Meta(md5="123"),
                    HashInfo("md5", "123"),
                ),
                ("dir", "z"): (
                    Meta(md5="456"),
                    HashInfo("md5", "456"),
                ),
                ("dir", "a"): (
                    Meta(md5="789"),
                    HashInfo("md5", "789"),
                ),
                ("b",): (Meta(md5="abc"), HashInfo("md5", "abc")),
                ("a",): (Meta(md5="def"), HashInfo("md5", "def")),
                ("z",): (Meta(md5="ghi"), HashInfo("md5", "ghi")),
                ("dir", "subdir", "b"): (
                    Meta(md5="jkl"),
                    HashInfo("md5", "jkl"),
                ),
                ("dir", "subdir", "z"): (
                    Meta(md5="mno"),
                    HashInfo("md5", "mno"),
                ),
                ("dir", "subdir", "a"): (
                    Meta(md5="pqr"),
                    HashInfo("md5", "pqr"),
                ),
            },
        ),
    ],
)
def test_list(lst, trie_dict):
    tree = Tree.from_list(lst)
    assert tree.as_dict() == trie_dict
    assert tree.as_list() == sorted(lst, key=itemgetter("relpath"))


@pytest.mark.parametrize(
    "lst, trie_dict",
    [
        ([], {}),
        (
            [
                {"md5": "def", "relpath": "zzz"},
                {"md5": "123", "relpath": "foo"},
                {"md5": "abc", "relpath": "aaa"},
                {"md5": "456", "relpath": "bar"},
            ],
            {
                ("zzz",): (Meta(md5="def"), HashInfo("md5-dos2unix", "def")),
                ("foo",): (Meta(md5="123"), HashInfo("md5-dos2unix", "123")),
                ("bar",): (Meta(md5="456"), HashInfo("md5-dos2unix", "456")),
                ("aaa",): (Meta(md5="abc"), HashInfo("md5-dos2unix", "abc")),
            },
        ),
    ],
)
def test_list_dos2unix(lst, trie_dict):
    tree = Tree.from_list(lst, hash_name="md5-dos2unix")
    assert tree.as_dict() == trie_dict
    assert tree.as_list() == sorted(lst, key=itemgetter("relpath"))


@pytest.mark.parametrize(
    "trie_dict, nfiles",
    [
        ({}, 0),
        (
            {
                ("a",): (Meta(size=1), HashInfo("md5", "abc")),
                ("b",): (Meta(size=2), HashInfo("md5", "def")),
                ("c",): (Meta(size=3), HashInfo("md5", "ghi")),
                ("dir", "foo"): (Meta(size=4), HashInfo("md5", "jkl")),
                ("dir", "bar"): (Meta(size=5), HashInfo("md5", "mno")),
                ("dir", "baz"): (Meta(size=6), HashInfo("md5", "pqr")),
            },
            6,
        ),
        (
            {
                ("a",): (Meta(size=1), HashInfo("md5", "abc")),
                ("b",): (Meta(), HashInfo("md5", "def")),
            },
            2,
        ),
    ],
)
def test_nfiles(trie_dict, nfiles):
    tree = Tree()
    tree._dict = trie_dict
    assert len(tree) == nfiles


@pytest.mark.parametrize(
    "trie_dict",
    [
        {},
        {
            ("a",): (Meta(md5="abc"), HashInfo("md5", "abc")),
            ("b",): (Meta(md5="def"), HashInfo("md5", "def")),
            ("c",): (Meta(md5="ghi"), HashInfo("md5", "ghi")),
            ("dir", "foo"): (Meta(md5="jkl"), HashInfo("md5", "jkl")),
            ("dir", "bar"): (Meta(md5="mno"), HashInfo("md5", "mno")),
            ("dir", "baz"): (Meta(md5="pqr"), HashInfo("md5", "pqr")),
            ("dir", "subdir", "1"): (Meta(md5="stu"), HashInfo("md5", "stu")),
            ("dir", "subdir", "2"): (Meta(md5="vwx"), HashInfo("md5", "vwx")),
            ("dir", "subdir", "3"): (Meta(md5="yz"), HashInfo("md5", "yz")),
        },
    ],
)
def test_items(trie_dict):
    tree = Tree()
    tree._dict = trie_dict
    assert list(tree) == [(key, value[0], value[1]) for key, value in trie_dict.items()]


@pytest.mark.parametrize(
    "ancestor_dict, our_dict, their_dict, merged_dict",
    [
        ({}, {}, {}, {}),
        (
            {("foo",): HashInfo("md5", "123")},
            {
                ("foo",): HashInfo("md5", "123"),
                ("bar",): HashInfo("md5", "345"),
            },
            {
                ("foo",): HashInfo("md5", "123"),
                ("baz",): HashInfo("md5", "678"),
            },
            {
                ("foo",): HashInfo("md5", "123"),
                ("bar",): HashInfo("md5", "345"),
                ("baz",): HashInfo("md5", "678"),
            },
        ),
        (
            {
                ("common",): HashInfo("md5", "123"),
                ("subdir", "foo"): HashInfo("md5", "456"),
            },
            {
                ("common",): HashInfo("md5", "123"),
                ("subdir", "foo"): HashInfo("md5", "456"),
                ("subdir", "bar"): HashInfo("md5", "789"),
            },
            {
                ("common",): HashInfo("md5", "123"),
                ("subdir", "foo"): HashInfo("md5", "456"),
                ("subdir", "baz"): HashInfo("md5", "91011"),
            },
            {
                ("common",): HashInfo("md5", "123"),
                ("subdir", "foo"): HashInfo("md5", "456"),
                ("subdir", "bar"): HashInfo("md5", "789"),
                ("subdir", "baz"): HashInfo("md5", "91011"),
            },
        ),
        (
            {},
            {("foo",): HashInfo("md5", "123")},
            {("bar",): HashInfo("md5", "456")},
            {
                ("foo",): HashInfo("md5", "123"),
                ("bar",): HashInfo("md5", "456"),
            },
        ),
        (
            {},
            {},
            {("bar",): HashInfo("md5", "123")},
            {("bar",): HashInfo("md5", "123")},
        ),
        (
            {},
            {("bar",): HashInfo("md5", "123")},
            {},
            {("bar",): HashInfo("md5", "123")},
        ),
        (
            {
                ("subdir", "foo"): HashInfo("md5", "123"),
                ("subdir", "bar"): HashInfo("md5", "456"),
                ("subdir", "baz"): HashInfo("md5", "789"),
            },
            {
                ("subdir", "foo"): HashInfo("md5", "123"),
                ("subdir", "baz"): HashInfo("md5", "789"),
            },
            {
                ("subdir", "foo"): HashInfo("md5", "123"),
                ("subdir", "bar"): HashInfo("md5", "456"),
            },
            {
                ("subdir", "foo"): HashInfo("md5", "123"),
            },
        ),
        (
            {
                ("subdir", "foo"): HashInfo("md5", "123"),
            },
            {
                ("subdir", "foo"): HashInfo("md5", "456"),
            },
            {
                ("subdir", "foo"): HashInfo("md5", "123"),
                ("subdir", "bar"): HashInfo("md5", "789"),
            },
            {
                ("subdir", "foo"): HashInfo("md5", "456"),
                ("subdir", "bar"): HashInfo("md5", "789"),
            },
        ),
        (
            {
                ("subdir", "foo"): HashInfo("md5", "123"),
                ("subdir", "bar"): HashInfo("md5", "456"),
            },
            {
                ("subdir", "foo"): HashInfo("md5", "123"),
            },
            {
                ("subdir", "bar"): HashInfo("md5", "456"),
            },
            {},
        ),
        (
            {
                "foo": HashInfo("md5", "123"),
                "bar": HashInfo("md5", "456"),
            },
            {
                "foo": HashInfo("md5", "789"),
                "bar": HashInfo("md5", "456"),
            },
            {
                "foo": HashInfo("md5", "123"),
                "bar": HashInfo("md5", "101112"),
            },
            {
                "foo": HashInfo("md5", "789"),
                "bar": HashInfo("md5", "101112"),
            },
        ),
        (
            {},
            {
                "foo": HashInfo("md5", "123"),
            },
            {
                "foo": HashInfo("md5", "123"),
            },
            {
                "foo": HashInfo("md5", "123"),
            },
        ),
        (
            {
                "foo": HashInfo("md5", "123"),
            },
            {
                "foo": HashInfo("md5", "456"),
            },
            {
                "foo": HashInfo("md5", "456"),
            },
            {
                "foo": HashInfo("md5", "456"),
            },
        ),
    ],
)
def test_merge(ancestor_dict, our_dict, their_dict, merged_dict):
    actual = _merge(
        ancestor_dict,
        our_dict,
        their_dict,
        allowed=["add", "remove", "change"],
    )
    assert actual == merged_dict


@pytest.mark.parametrize(
    "ancestor_dict, our_dict, their_dict, error",
    [
        (
            {
                ("subdir", "foo"): HashInfo("md5", "123"),
            },
            {
                ("subdir", "foo"): HashInfo("md5", "456"),
            },
            {
                ("subdir", "foo"): HashInfo("md5", "789"),
            },
            "subdir/foo",
        ),
        (
            {},
            {
                ("subdir", "foo"): HashInfo("md5", "456"),
            },
            {
                ("subdir", "foo"): HashInfo("md5", "789"),
            },
            "subdir/foo",
        ),
        (
            {
                ("subdir", "foo"): HashInfo("md5", "123"),
            },
            {
                ("subdir", "foo"): HashInfo("md5", "456"),
            },
            {},
            "subdir/foo",
        ),
        (
            {
                "foo": HashInfo("md5", "123"),
                ("subdir", "foo"): HashInfo("md5", "123"),
            },
            {
                "foo": HashInfo("md5", "123"),
                ("subdir", "foo"): HashInfo("md5", "456"),
            },
            {
                "foo": HashInfo("md5", "123"),
            },
            "subdir/foo",
        ),
        (
            {
                "foo": HashInfo("md5", "123"),
                "bar": HashInfo("md5", "456"),
            },
            {},
            {},
            "both deleted: 'foo'",
        ),
    ],
)
def test_merge_conflict(ancestor_dict, our_dict, their_dict, error):
    with pytest.raises(MergeError) as excinfo:
        _merge(
            ancestor_dict,
            our_dict,
            their_dict,
            allowed=["add", "remove", "change"],
        )
    error_msg = "unable to auto-merge the following paths:\n" + error
    assert error_msg == str(excinfo.value)
