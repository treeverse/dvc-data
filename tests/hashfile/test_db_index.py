from contextlib import closing

import pytest

from dvc_data.hashfile.db.index import ObjectDBIndex


@pytest.fixture
def index(tmp_path):
    with closing(ObjectDBIndex(tmp_path, "foo")) as _index:
        yield _index


def test_roundtrip(request, tmp_path, index):
    expected_dir = {"1234.dir"}
    expected_file = {"5678"}
    index.update(expected_dir, expected_file)

    new_index = ObjectDBIndex(tmp_path, "foo")
    request.addfinalizer(new_index.close)

    assert set(new_index.dir_hashes()) == expected_dir
    assert set(new_index.hashes()) == expected_dir | expected_file


def test_clear(index):
    index.update(["1234.dir"], ["5678"])
    index.clear()
    assert not list(index.hashes())


def test_update(index):
    expected_dir = {"1234.dir"}
    expected_file = {"5678"}
    index.update(expected_dir, expected_file)
    assert set(index.dir_hashes()) == expected_dir
    assert set(index.hashes()) == expected_dir | expected_file


def test_intersection(index):
    hashes = (str(i) for i in range(2000))
    expected = {str(i) for i in range(1000)}
    index.update([], hashes)
    assert set(index.intersection(expected)) == expected


def test_legacy_pickled_index_is_dropped(tmp_path):
    """An index written by an older, pickle-serializing dvc-data is discarded.

    The index is a regenerable cache under `tmp_dir`, so refusing to unpickle
    it costs a re-index rather than data. `dir_hashes` must not raise while the
    stale entries are being evicted.
    """
    import diskcache

    from dvc_data.hashfile.cache import Disk

    index_dir = tmp_path / ObjectDBIndex.INDEX_DIR / "foo"
    index_dir.mkdir(parents=True)
    with diskcache.Cache(str(index_dir), disk=Disk, disk_pickle_protocol=4) as cache:
        cache.disk._type = cache._type = "index"
        cache["1234.dir"] = True
        cache["5678"] = False

    with closing(ObjectDBIndex(tmp_path, "foo")) as index:
        assert list(index.dir_hashes()) == []
        assert index.intersection({"1234.dir", "5678"}) is not None

        # Re-indexing repopulates it, now without pickle.
        index.update({"1234.dir"}, {"5678"})
        assert set(index.dir_hashes()) == {"1234.dir"}
