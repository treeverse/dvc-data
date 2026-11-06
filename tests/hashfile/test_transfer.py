import pytest
from dvc_objects.fs.local import LocalFileSystem

from dvc_data.hashfile.db import HashFileDB, add_update_tree
from dvc_data.hashfile.db.local import LocalHashFileDB
from dvc_data.hashfile.hash_info import HashInfo
from dvc_data.hashfile.transfer import TransferResult, transfer
from dvc_data.hashfile.tree import Tree


@pytest.mark.parametrize("odb_cls", [HashFileDB, LocalHashFileDB])
@pytest.mark.parametrize("fail_shared", [True, False])
def test_transfer_shared_file(tmp_path, odb_cls, fail_shared):
    fs = LocalFileSystem(jobs=1)
    src = odb_cls(fs, str(tmp_path / "src"))
    dest = odb_cls(fs, str(tmp_path / "dest"))
    shared = HashInfo("md5", "acbd18db4cc2f85cedef654fccc4a4d8")
    other = HashInfo("md5", "37b51d194a7513e45b56f6524f2d51f2")
    src.add_bytes(shared.value, b"foo")
    src.add_bytes(other.value, b"bar")

    trees = []
    for name, hash_info in [("first", shared), ("second", shared), ("other", other)]:
        tree = Tree.from_list([{"md5": hash_info.value, "relpath": name}])
        tree.digest()
        trees.append(add_update_tree(src, tree))
    shared_dirs = {tree.hash_info for tree in trees[:2]}
    independent_dir = trees[2].hash_info
    objects = shared_dirs | {shared, other, independent_dir}

    def validate_status(status):
        assert status.new == objects
        if fail_shared:
            # Model a source file disappearing after the initial status check.
            src.delete(shared.value)

    result = transfer(
        src,
        dest,
        objects,
        jobs=1,
        validate_status=validate_status,
    )

    assert dest.exists(independent_dir.value)
    assert dest.fs.cat(dest.oid_to_path(other.value)) == b"bar"
    if fail_shared:
        assert not dest.exists(shared.value)
        assert all(not dest.exists(hi.value) for hi in shared_dirs)
        assert result == TransferResult(
            {other, independent_dir}, {shared, *shared_dirs}
        )

        # A later retry must be able to restore both incomplete directories.
        src.add_bytes(shared.value, b"foo")
        result = transfer(src, dest, objects, jobs=1)
        assert result == TransferResult({shared, *shared_dirs}, set())
    else:
        assert result == TransferResult(objects, set())
    assert all(dest.exists(hi.value) for hi in objects)
    assert dest.fs.cat(dest.oid_to_path(shared.value)) == b"foo"
