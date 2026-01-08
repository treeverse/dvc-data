import pytest
from dvc_objects.fs.local import LocalFileSystem

from dvc_data.hashfile.db import HashFileDB
from dvc_data.hashfile.hash_info import HashInfo
from dvc_data.hashfile.meta import Meta
from dvc_data.index import (
    DataIndex,
    DataIndexEntry,
    FileStorage,
    ObjectStorage,
    StorageInfo,
    StorageMapping,
)


def test_map_get(tmp_path, odb):
    smap = StorageMapping()

    fs = LocalFileSystem()

    data = FileStorage(key=(), fs=fs, path=str(tmp_path))
    cache = FileStorage(key=("dir",), fs=fs, path=str(tmp_path))
    remote = FileStorage(key=("dir", "subdir"), fs=fs, path=str(tmp_path))
    foo_cache = ObjectStorage(key=("dir", "foo"), odb=odb)

    smap[()] = StorageInfo(data=data)
    smap[("dir",)] = StorageInfo(cache=cache)
    smap[("dir", "subdir")] = StorageInfo(remote=remote)
    smap[("dir", "foo")] = StorageInfo(cache=foo_cache)

    sinfo = smap[()]
    assert sinfo.data == data
    assert sinfo.cache is None
    assert sinfo.remote is None

    sinfo = smap[("dir",)]
    assert sinfo.data == data
    assert sinfo.cache == cache
    assert sinfo.remote is None

    sinfo = smap[("dir", "foo")]
    assert sinfo.data == data
    assert sinfo.cache == foo_cache
    assert sinfo.remote is None

    sinfo = smap[("dir", "subdir")]
    assert sinfo.data == data
    assert sinfo.cache == cache
    assert sinfo.remote == remote

    sinfo = smap[("dir", "subdir", "file")]
    assert sinfo.data == data
    assert sinfo.cache == cache
    assert sinfo.remote == remote

    sinfo = smap[("dir", "subdir", "subsubdir", "otherfile")]
    assert sinfo.data == data
    assert sinfo.cache == cache
    assert sinfo.remote == remote


class TestObjectStorageBulkExists:
    def test_empty_entries(self, odb):
        storage = ObjectStorage(key=(), odb=odb)
        result = storage.bulk_exists([])
        assert result == {}

    def test_entries_without_hash(self, odb):
        storage = ObjectStorage(key=(), odb=odb)
        entry = DataIndexEntry(key=("foo",), meta=Meta())
        result = storage.bulk_exists([entry])
        assert result == {entry: False}

    def test_entries_exist_in_odb(self, odb):
        storage = ObjectStorage(key=(), odb=odb)
        entry = DataIndexEntry(
            key=("foo",),
            hash_info=HashInfo("md5", "d3b07384d113edec49eaa6238ad5ff00"),
        )
        result = storage.bulk_exists([entry])
        assert result == {entry: True}

    def test_entries_not_in_odb(self, make_odb):
        empty_odb = make_odb()
        storage = ObjectStorage(key=(), odb=empty_odb)
        entry = DataIndexEntry(
            key=("foo",),
            hash_info=HashInfo("md5", "nonexistent"),
        )
        result = storage.bulk_exists([entry])
        assert result == {entry: False}

    def test_with_index_no_refresh(self, odb):
        index = DataIndex()
        key = odb._oid_parts("d3b07384d113edec49eaa6238ad5ff00")
        index[key] = DataIndexEntry(key=key)

        storage = ObjectStorage(key=(), odb=odb, index=index)
        entry_exists = DataIndexEntry(
            key=("foo",),
            hash_info=HashInfo("md5", "d3b07384d113edec49eaa6238ad5ff00"),
        )
        entry_not_in_index = DataIndexEntry(
            key=("bar",),
            hash_info=HashInfo("md5", "c157a79031e1c40f85931829bc5fc552"),
        )

        result = storage.bulk_exists([entry_exists, entry_not_in_index], refresh=False)
        assert result[entry_exists] is True
        assert result[entry_not_in_index] is False

    def test_with_index_refresh_existing(self, odb):
        index = DataIndex()
        storage = ObjectStorage(key=(), odb=odb, index=index)

        entry_exists = DataIndexEntry(
            key=("foo",),
            hash_info=HashInfo("md5", "d3b07384d113edec49eaa6238ad5ff00"),
        )

        result = storage.bulk_exists([entry_exists], refresh=True)
        assert result[entry_exists] is True

        key_exists = odb._oid_parts("d3b07384d113edec49eaa6238ad5ff00")
        assert key_exists in index

    def test_mixed_entries(self, odb):
        storage = ObjectStorage(key=(), odb=odb)
        entry_with_hash = DataIndexEntry(
            key=("foo",),
            hash_info=HashInfo("md5", "d3b07384d113edec49eaa6238ad5ff00"),
        )
        entry_without_hash = DataIndexEntry(key=("bar",), meta=Meta())

        result = storage.bulk_exists([entry_with_hash, entry_without_hash])
        assert result[entry_with_hash] is True
        assert result[entry_without_hash] is False

    def test_multiple_entries(self, odb):
        storage = ObjectStorage(key=(), odb=odb)
        entries = [
            DataIndexEntry(
                key=("foo",),
                hash_info=HashInfo("md5", "d3b07384d113edec49eaa6238ad5ff00"),
            ),
            DataIndexEntry(
                key=("bar",),
                hash_info=HashInfo("md5", "c157a79031e1c40f85931829bc5fc552"),
            ),
            DataIndexEntry(
                key=("baz",),
                hash_info=HashInfo("md5", "258622b1688250cb619f3c9ccaefb7eb"),
            ),
        ]

        result = storage.bulk_exists(entries)
        assert all(result[e] is True for e in entries)

    @pytest.mark.parametrize("use_index", [True, False])
    @pytest.mark.parametrize("refresh", [True, False])
    def test_duplicate_hashes_exist(self, odb, use_index, refresh):
        """Multiple entries with same hash should all return True if exists."""
        index = None
        if use_index:
            index = DataIndex()
            key = odb._oid_parts("d3b07384d113edec49eaa6238ad5ff00")
            index[key] = DataIndexEntry(key=key)

        storage = ObjectStorage(key=(), odb=odb, index=index)
        entries = [
            DataIndexEntry(
                key=("foo",),
                hash_info=HashInfo("md5", "d3b07384d113edec49eaa6238ad5ff00"),
            ),
            DataIndexEntry(
                key=("bar",),
                hash_info=HashInfo("md5", "d3b07384d113edec49eaa6238ad5ff00"),
            ),
        ]

        result = storage.bulk_exists(entries, refresh=refresh)
        assert result == {entries[0]: True, entries[1]: True}

    @pytest.mark.parametrize("use_index", [True, False])
    @pytest.mark.parametrize("refresh", [True, False])
    def test_duplicate_hashes_not_exist(self, odb, use_index, refresh):
        """Multiple entries with same hash should all return False if not exists."""
        index = DataIndex() if use_index else None
        storage = ObjectStorage(key=(), odb=odb, index=index)
        entries = [
            DataIndexEntry(
                key=("foo",),
                hash_info=HashInfo("md5", "00000000000000000000000000000000"),
            ),
            DataIndexEntry(
                key=("bar",),
                hash_info=HashInfo("md5", "00000000000000000000000000000000"),
            ),
        ]

        result = storage.bulk_exists(entries, refresh=refresh)
        assert result == {entries[0]: False, entries[1]: False}

    def test_bulk_check_with_ls_not_implemented(self, tmp_path_factory):
        class NonTraversableFileSystem(LocalFileSystem):
            def ls(self, *args, **kwargs):
                raise NotImplementedError

        index = DataIndex()
        path = tmp_path_factory.mktemp("odb")
        odb = HashFileDB(fs=NonTraversableFileSystem(), path=path)
        storage = ObjectStorage(key=(), odb=odb, index=index)
        entries = [
            DataIndexEntry(
                key=("foo",),
                hash_info=HashInfo("md5", "d3b07384d113edec49eaa6238ad5ff00"),
            ),
            DataIndexEntry(
                key=("bar",),
                hash_info=HashInfo("md5", "c157a79031e1c40f85931829bc5fc552"),
            ),
        ]

        result = storage.bulk_exists(entries, refresh=True)
        assert result == {entries[0]: False, entries[1]: False}


class TestStorageMappingBulkExists:
    def test_bulk_cache_exists_empty(self, odb):
        smap = StorageMapping()
        smap.add_cache(ObjectStorage(key=(), odb=odb))
        result = smap.bulk_cache_exists([])
        assert result == {}

    def test_bulk_remote_exists_empty(self, odb):
        smap = StorageMapping()
        smap.add_remote(ObjectStorage(key=(), odb=odb))
        result = smap.bulk_remote_exists([])
        assert result == {}

    def test_bulk_cache_exists_all_exist(self, make_odb):
        cache_odb = make_odb()
        cache_odb.add_bytes("d3b07384d113edec49eaa6238ad5ff00", b"foo\n")
        cache_odb.add_bytes("c157a79031e1c40f85931829bc5fc552", b"bar\n")

        smap = StorageMapping()
        smap.add_cache(ObjectStorage(key=(), odb=cache_odb))

        entries = [
            DataIndexEntry(
                key=("foo",),
                hash_info=HashInfo("md5", "d3b07384d113edec49eaa6238ad5ff00"),
            ),
            DataIndexEntry(
                key=("bar",),
                hash_info=HashInfo("md5", "c157a79031e1c40f85931829bc5fc552"),
            ),
        ]

        result = smap.bulk_cache_exists(entries)
        assert all(result[e] is True for e in entries)

    def test_bulk_remote_exists_all_exist(self, odb):
        smap = StorageMapping()
        smap.add_remote(ObjectStorage(key=(), odb=odb))

        entries = [
            DataIndexEntry(
                key=("foo",),
                hash_info=HashInfo("md5", "d3b07384d113edec49eaa6238ad5ff00"),
            ),
            DataIndexEntry(
                key=("bar",),
                hash_info=HashInfo("md5", "c157a79031e1c40f85931829bc5fc552"),
            ),
        ]

        result = smap.bulk_remote_exists(entries)
        assert all(result[e] is True for e in entries)

    def test_bulk_cache_exists_missing_storage(self, odb):
        smap = StorageMapping()
        smap.add_remote(ObjectStorage(key=(), odb=odb))

        entry = DataIndexEntry(
            key=("foo",),
            hash_info=HashInfo("md5", "d3b07384d113edec49eaa6238ad5ff00"),
        )

        result = smap.bulk_cache_exists([entry])
        # no cache storage, should be skipped
        assert entry not in result

    def test_bulk_remote_exists_missing_storage(self, odb):
        smap = StorageMapping()
        smap.add_cache(ObjectStorage(key=(), odb=odb))

        entry = DataIndexEntry(
            key=("foo",),
            hash_info=HashInfo("md5", "d3b07384d113edec49eaa6238ad5ff00"),
        )

        result = smap.bulk_remote_exists([entry])
        # no remote storage, should be skipped
        assert entry not in result

    def test_bulk_exists_multiple_storages(self, make_odb):
        cache1 = make_odb()
        cache1.add_bytes("hash1", b"data1")
        cache2 = make_odb()
        cache2.add_bytes("hash2", b"data2")

        smap = StorageMapping()
        smap.add_cache(ObjectStorage(key=(), odb=cache1))
        smap.add_cache(ObjectStorage(key=("subdir",), odb=cache2))

        entry1 = DataIndexEntry(
            key=("foo",),
            hash_info=HashInfo("md5", "hash1"),
        )
        entry2 = DataIndexEntry(
            key=("subdir", "bar"),
            hash_info=HashInfo("md5", "hash2"),
        )

        result = smap.bulk_cache_exists([entry1, entry2])
        assert result[entry1] is True
        assert result[entry2] is True

    def test_bulk_exists_shared_odb(self, make_odb):
        odb = make_odb()
        odb.add_bytes("hash1", b"data1")
        odb.add_bytes("hash2", b"data2")

        smap = StorageMapping()
        # two logical storages, one physical ODB
        smap.add_cache(ObjectStorage(key=(), odb=odb))
        smap.add_cache(ObjectStorage(key=("subdir",), odb=odb))

        entry1 = DataIndexEntry(
            key=("foo",),
            hash_info=HashInfo("md5", "hash1"),
        )
        entry2 = DataIndexEntry(
            key=("subdir", "bar"),
            hash_info=HashInfo("md5", "hash2"),
        )

        result = smap.bulk_cache_exists([entry1, entry2])
        assert result[entry1] is True
        assert result[entry2] is True

    def test_bulk_cache_exists_with_file_storage(self, tmp_path):
        (tmp_path / "foo.txt").write_text("hello")
        fs = LocalFileSystem()

        smap = StorageMapping()
        smap.add_cache(FileStorage(key=(), fs=fs, path=str(tmp_path)))

        entry_exists = DataIndexEntry(key=("foo.txt",))
        entry_not_exists = DataIndexEntry(key=("bar.txt",))

        result = smap.bulk_cache_exists([entry_exists, entry_not_exists])
        assert result[entry_exists] is True
        assert result[entry_not_exists] is False
