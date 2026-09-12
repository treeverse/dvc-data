import pytest

from dvc_data.index import DataIndex, DataIndexEntry
from dvc_data.index.serialize import read_db, write_db


@pytest.mark.parametrize("new_keys", [[], [("new",)]])
def test_write_db_replaces_previous_snapshot(tmp_path, new_keys):
    path = str(tmp_path / "index")
    write_db(DataIndex({("old",): DataIndexEntry(key=("old",))}), path)
    updated = DataIndex({key: DataIndexEntry(key=key) for key in new_keys})

    write_db(updated, path)

    assert set(read_db(path)) == set(new_keys)


def test_failed_write_db_keeps_previous_snapshot(tmp_path, mocker):
    path = str(tmp_path / "index")
    write_db(DataIndex({("old",): DataIndexEntry(key=("old",))}), path)
    updated = DataIndex()

    def entries():
        yield ("new",), DataIndexEntry(key=("new",))
        raise OSError("index loading failed")

    mocker.patch.object(updated, "iteritems", side_effect=entries)
    with pytest.raises(OSError, match="index loading failed"):
        write_db(updated, path)

    assert set(read_db(path)) == {("old",)}
