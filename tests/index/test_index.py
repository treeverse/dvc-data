import pytest
from dvc_objects.fs.local import LocalFileSystem

from dvc_data.hashfile.hash_info import HashInfo
from dvc_data.hashfile.meta import Meta
from dvc_data.index import (
    DataIndex,
    DataIndexEntry,
    FileStorage,
    ObjectStorage,
    add,
    build,
    checkout,
    md5,
    read_db,
    read_json,
    save,
    update,
    view,
    write_db,
    write_json,
)


def test_index():
    index = DataIndex()
    index[("foo",)] = DataIndexEntry()


def test_md5(tmp_path):
    (tmp_path / "foo").write_bytes(b"foo\n")
    (tmp_path / "data").mkdir()
    (tmp_path / "data" / "bar").write_bytes(b"bar\n")
    (tmp_path / "data" / "baz").write_bytes(b"baz\n")

    fs = LocalFileSystem()

    index = build(str(tmp_path), fs)
    index = md5(index)
    assert index[("foo",)].hash_info == HashInfo(
        "md5",
        "d3b07384d113edec49eaa6238ad5ff00",
    )
    assert index[("data", "bar")].hash_info == HashInfo(
        "md5",
        "c157a79031e1c40f85931829bc5fc552",
    )
    assert index[("data", "baz")].hash_info == HashInfo(
        "md5",
        "258622b1688250cb619f3c9ccaefb7eb",
    )


def test_save(tmp_path, odb):
    (tmp_path / "foo").write_bytes(b"foo\n")
    (tmp_path / "data").mkdir()
    (tmp_path / "data" / "bar").write_bytes(b"bar\n")
    (tmp_path / "data" / "baz").write_bytes(b"baz\n")

    fs = LocalFileSystem()

    index = build(str(tmp_path), fs)
    index = md5(index)
    save(index, odb=odb)
    assert odb.exists("d3b07384d113edec49eaa6238ad5ff00")
    assert odb.exists("1f69c66028c35037e8bf67e5bc4ceb6a.dir")
    assert odb.exists("c157a79031e1c40f85931829bc5fc552")
    assert odb.exists("258622b1688250cb619f3c9ccaefb7eb")


@pytest.mark.parametrize("immutable", [True, False])
@pytest.mark.parametrize("name", ["md5", "md5-dos2unix"])
@pytest.mark.parametrize("matches", [True, False])
def test_md5_validates_existing_hash(tmp_path, monkeypatch, immutable, name, matches):
    (tmp_path / "foo").write_bytes(b"foo\n")
    fs = LocalFileSystem()
    monkeypatch.setattr(fs, "immutable", immutable, raising=False)
    index = build(str(tmp_path), fs)
    expected = HashInfo(
        name, "d3b07384d113edec49eaa6238ad5ff00" if matches else "0" * 32
    )
    index[("foo",)].hash_info = expected

    result = md5(index, name=name)

    assert result.storage_map is index.storage_map
    assert index[("foo",)].hash_info == expected
    if matches:
        assert result[("foo",)].hash_info == expected
    else:
        assert ("foo",) not in result


@pytest.mark.parametrize("immutable", [True, False])
def test_fetch_does_not_cache_mismatched_hash(
    tmp_path, make_odb, monkeypatch, immutable
):
    from dvc_data.index.fetch import collect, fetch

    (tmp_path / "foo").write_bytes(b"foo\n")
    fs = LocalFileSystem()
    monkeypatch.setattr(fs, "immutable", immutable, raising=False)
    index = build(str(tmp_path), fs)
    expected = "0" * 32
    index[("foo",)].hash_info = HashInfo("md5", expected)
    cache = make_odb()
    index.storage_map.add_cache(ObjectStorage((), cache))
    index.storage_map.add_remote(FileStorage((), fs, str(tmp_path)))

    transferred, _ = fetch(collect([index], "remote"))

    assert transferred == 0
    assert not cache.exists(expected)


def test_md5_preserves_legacy_hash(tmp_path, monkeypatch):
    (tmp_path / "foo").write_bytes(b"foo\r\n")
    fs = LocalFileSystem()
    monkeypatch.setattr(fs, "immutable", True, raising=False)
    index = build(str(tmp_path), fs)
    expected = HashInfo("md5-dos2unix", "d3b07384d113edec49eaa6238ad5ff00")
    index[("foo",)].hash_info = expected

    assert md5(index)[("foo",)].hash_info == expected


def test_add(tmp_path):
    (tmp_path / "foo").write_bytes(b"foo\n")
    (tmp_path / "data").mkdir()
    (tmp_path / "data" / "bar").write_bytes(b"bar\n")
    (tmp_path / "data" / "baz").write_bytes(b"baz\n")

    fs = LocalFileSystem()
    index = build(str(tmp_path), fs)
    index = DataIndex()

    add(index, str(tmp_path / "foo"), fs, ("foo",))
    assert len(index) == 1
    assert index[("foo",)].meta.size == 4
    assert index.storage_map.get_data(index[("foo",)]) == (
        fs,
        str(tmp_path / "foo"),
    )

    add(index, str(tmp_path / "data"), fs, ("data",))
    assert len(index) == 4
    assert index[("foo",)].meta.size == 4
    assert index.storage_map.get_data(index[("foo",)]) == (
        fs,
        str(tmp_path / "foo"),
    )
    assert index[("data",)].meta.isdir
    assert index[("data", "bar")].meta.size == 4
    assert index.storage_map.get_data(index[("data", "bar")]) == (
        fs,
        str(tmp_path / "data" / "bar"),
    )
    assert index[("data", "baz")].meta.size == 4
    assert index.storage_map.get_data(index[("data", "baz")]) == (
        fs,
        str(tmp_path / "data" / "baz"),
    )


def test_fetch(tmp_path, make_odb, odb):
    from dvc_data.index.fetch import collect, fetch

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
    cache_odb = make_odb()
    index.storage_map.add_cache(ObjectStorage((), cache_odb))
    index.storage_map.add_remote(ObjectStorage((), odb))

    (tmp_path / "fetched").mkdir()
    data = collect([index], "remote")
    fetch(data)
    diff = checkout.compare(None, index)
    checkout.apply(
        diff,
        str(tmp_path / "checkout"),
        LocalFileSystem(),
        storage="cache",
    )
    assert (tmp_path / "checkout" / "foo").read_text() == "foo\n"
    assert (tmp_path / "checkout" / "data").is_dir()
    assert (tmp_path / "checkout" / "data" / "bar").read_text() == "bar\n"
    assert (tmp_path / "checkout" / "data" / "baz").read_text() == "baz\n"
    assert set((tmp_path / "checkout").iterdir()) == {
        (tmp_path / "checkout" / "foo"),
        (tmp_path / "checkout" / "data"),
    }
    assert set((tmp_path / "checkout" / "data").iterdir()) == {
        (tmp_path / "checkout" / "data" / "bar"),
        (tmp_path / "checkout" / "data" / "baz"),
    }


def test_push(tmp_path, make_odb, odb):
    from dvc_data.index.collect import collect
    from dvc_data.index.push import push

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
    remote_odb = make_odb()
    index.storage_map.add_cache(ObjectStorage((), odb))
    index.storage_map.add_remote(ObjectStorage((), remote_odb))

    data = collect([index], "remote")
    push(data)
    odb.clear()
    assert not list(odb.all())
    assert list(remote_odb.all())

    diff = checkout.compare(None, index)
    checkout.apply(
        diff,
        str(tmp_path / "checkout"),
        LocalFileSystem(),
        storage="remote",
    )
    assert (tmp_path / "checkout" / "foo").read_text() == "foo\n"
    assert (tmp_path / "checkout" / "data").is_dir()
    assert (tmp_path / "checkout" / "data" / "bar").read_text() == "bar\n"
    assert (tmp_path / "checkout" / "data" / "baz").read_text() == "baz\n"
    assert set((tmp_path / "checkout").iterdir()) == {
        (tmp_path / "checkout" / "foo"),
        (tmp_path / "checkout" / "data"),
    }
    assert set((tmp_path / "checkout" / "data").iterdir()) == {
        (tmp_path / "checkout" / "data" / "bar"),
        (tmp_path / "checkout" / "data" / "baz"),
    }


@pytest.mark.parametrize(
    "write, read",
    [
        (write_db, read_db),
        (write_json, read_json),
    ],
)
def test_write_read(odb, tmp_path, write, read):
    index = DataIndex(
        {
            ("foo",): DataIndexEntry(),
            ("data",): DataIndexEntry(),
        },
    )
    index.load()

    path = str(tmp_path / "index")

    write(index, path)
    new_index = read(path)
    assert len(index) == len(new_index)
    for key, entry in new_index.iteritems():
        assert index[key].meta == entry.meta
        assert index[key].hash_info == entry.hash_info


@pytest.mark.parametrize(
    "keys, filter_fn, ensure_loaded",
    [
        (
            {
                ("foo",),
                ("dir", "subdir", "bar"),
                ("dir", "subdir", "bar", "bar"),
                ("dir", "subdir", "bar", "baz"),
            },
            lambda k: True,
            True,
        ),
        (
            {
                ("foo",),
                ("dir", "subdir", "bar"),
            },
            lambda k: True,
            False,
        ),
        (
            set(),
            lambda k: False,
            True,
        ),
        (
            set(),
            lambda k: False,
            False,
        ),
    ],
)
def test_view_iteritems(odb, keys, filter_fn, ensure_loaded):
    index = DataIndex(
        {
            ("foo",): DataIndexEntry(
                key=("foo",),
                hash_info=HashInfo(
                    name="md5", value="d3b07384d113edec49eaa6238ad5ff00"
                ),
            ),
            ("dir", "subdir", "bar"): DataIndexEntry(
                key=("dir", "subdir", "bar"),
                hash_info=HashInfo(
                    name="md5",
                    value="1f69c66028c35037e8bf67e5bc4ceb6a.dir",
                ),
                meta=Meta(isdir=True),
            ),
        }
    )
    index.storage_map.add_cache(ObjectStorage((), odb))
    index_view = view(index, filter_fn)
    assert keys == {
        key for key, _ in index_view._iteritems(ensure_loaded=ensure_loaded)
    }


def test_view(odb):
    expected_key = ("dir", "subdir", "bar")
    expected_entry = DataIndexEntry(
        key=expected_key,
        meta=Meta(isdir=True),
        hash_info=HashInfo(
            name="md5",
            value="1f69c66028c35037e8bf67e5bc4ceb6a.dir",
        ),
    )
    index = DataIndex(
        {
            ("foo",): DataIndexEntry(
                key=("foo",),
                hash_info=HashInfo(
                    name="md5", value="d3b07384d113edec49eaa6238ad5ff00"
                ),
            ),
            expected_key: expected_entry,
        }
    )
    index.storage_map.add_cache(ObjectStorage((), odb))
    index_view = view(index, lambda k: "dir" in k)
    assert {expected_key} == set(index_view.keys())
    assert expected_key in index_view
    assert ("foo",) not in index_view
    assert len(index_view) == 1

    # iteritems() should ensure dirs are loaded
    assert len(list(index_view.iteritems())) == 3
    assert index_view[expected_key] == expected_entry
    assert index_view[expected_key] is index[expected_key]


def test_view_ls(odb):
    index = DataIndex(
        {
            ("foo",): DataIndexEntry(
                hash_info=HashInfo(
                    name="md5", value="d3b07384d113edec49eaa6238ad5ff00"
                ),
            ),
            ("dir", "subdir", "bar"): DataIndexEntry(
                hash_info=HashInfo(
                    name="md5",
                    value="1f69c66028c35037e8bf67e5bc4ceb6a.dir",
                ),
            ),
        }
    )
    index.storage_map.add_cache(ObjectStorage((), odb))
    index_view = view(index, lambda k: "dir" in k)
    assert list(index_view.ls((), detail=False)) == [("dir",)]
    assert list(index_view.ls(("dir",), detail=False)) == [
        (
            "dir",
            "subdir",
        )
    ]
    assert list(index_view.ls(("dir", "subdir"), detail=False)) == [
        ("dir", "subdir", "bar")
    ]


def test_view_traverse(odb):
    index = DataIndex(
        {
            ("foo",): DataIndexEntry(
                hash_info=HashInfo(
                    name="md5", value="d3b07384d113edec49eaa6238ad5ff00"
                ),
            ),
            ("dir", "subdir", "bar"): DataIndexEntry(
                hash_info=HashInfo(
                    name="md5",
                    value="1f69c66028c35037e8bf67e5bc4ceb6a.dir",
                ),
            ),
        }
    )
    index.storage_map.add_cache(ObjectStorage((), odb))
    index_view = view(index, lambda k: "dir" in k)

    keys = []

    def node_factory(_, key, children, *args):
        if key:
            keys.append(key)
        list(children)

    index_view.traverse(node_factory)
    assert keys == [
        ("dir",),
        ("dir", "subdir"),
        ("dir", "subdir", "bar"),
    ]


def test_update(tmp_path):
    (tmp_path / "foo").write_bytes(b"foo\n")
    (tmp_path / "data").mkdir()
    (tmp_path / "data" / "bar").write_bytes(b"bar\n")
    (tmp_path / "data" / "baz").write_bytes(b"baz\n")

    fs = LocalFileSystem()

    old = build(str(tmp_path), fs)
    old = md5(old)

    index = build(str(tmp_path), fs)
    update(index, old)
    assert index[("foo",)].hash_info == HashInfo(
        "md5",
        "d3b07384d113edec49eaa6238ad5ff00",
    )
    assert index[("data", "bar")].hash_info == HashInfo(
        "md5",
        "c157a79031e1c40f85931829bc5fc552",
    )
    assert index[("data", "baz")].hash_info == HashInfo(
        "md5",
        "258622b1688250cb619f3c9ccaefb7eb",
    )


def test_open(tmp_path):
    path = str(tmp_path / "index")
    index = DataIndex.open(path)

    assert not list(index.iteritems())

    key = ("foo",)
    entry1 = DataIndexEntry(key=key, meta=Meta(isdir=True))
    index[key] = entry1
    assert index[key] == entry1

    entry2 = DataIndexEntry(key=key)
    index[key] = entry2
    assert index[key] == entry2

    index.commit()
    assert index._trie._cache
    index.close()
    assert not index._trie._cache

    index = DataIndex.open(path)
    index[key] = entry2
    assert index[key] == entry2

    index[key] = entry1
    assert index[key] == entry1

    assert index._trie._cache
    index.close()
    assert not index._trie._cache
