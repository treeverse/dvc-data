from collections import defaultdict
from typing import TYPE_CHECKING, Optional

from fsspec.callbacks import DEFAULT_CALLBACK

from dvc_data.hashfile.hash import DEFAULT_ALGORITHM, hash_file
from dvc_data.hashfile.meta import Meta
from dvc_data.hashfile.tree import Tree

if TYPE_CHECKING:
    from dvc_objects.fs.base import FileSystem
    from fsspec import Callback

    from dvc_data.hashfile.db import HashFileDB
    from dvc_data.hashfile.state import StateBase

    from .index import BaseDataIndex, DataIndex, DataIndexKey


def _meta_matches(fs, path, old_meta):
    try:
        info = fs.info(path)
    except FileNotFoundError:
        return False

    if getattr(fs, "immutable", False):
        return True

    new_meta = Meta.from_info(info, fs.protocol)
    old = getattr(old_meta, fs.PARAM_CHECKSUM, None) if old_meta else None
    new = getattr(new_meta, fs.PARAM_CHECKSUM, None)
    if not old or not new:
        return None

    return old == new


def md5(
    index: "BaseDataIndex",
    state: Optional["StateBase"] = None,
    storage: str = "data",
    name: str = DEFAULT_ALGORITHM,
) -> "DataIndex":
    from .index import DataIndex, DataIndexEntry

    ret = DataIndex()

    for _, entry in index.iteritems():
        if entry.meta and entry.meta.isdir:
            ret.add(entry)
            continue

        hash_info = None
        if entry.hash_info and entry.hash_info.name in ("md5", "md5-dos2unix"):
            hash_info = entry.hash_info

        try:
            fs, path = index.storage_map.get_storage(entry, storage)
        except ValueError:
            continue

        matches = _meta_matches(fs, path, entry.meta)
        if matches is False:
            continue

        try:
            hash_name = hash_info.name if hash_info and hash_info.name else name
            _, hi = hash_file(path, fs, hash_name, state=state)
        except FileNotFoundError:
            continue

        if hash_info and hi != hash_info:
            continue

        ret.add(
            DataIndexEntry(
                key=entry.key,
                meta=entry.meta,
                hash_info=hi,
            )
        )

    ret.storage_map = index.storage_map
    return ret


def build_tree(
    index: "BaseDataIndex",
    prefix: "DataIndexKey",
    name: str = DEFAULT_ALGORITHM,
) -> tuple["Meta", Tree]:
    tree_meta = Meta(size=0, nfiles=0, isdir=True)
    assert tree_meta.size is not None
    assert tree_meta.nfiles is not None
    tree = Tree()
    for key, entry in index.iteritems(prefix=prefix):
        if key == prefix or (entry.meta and entry.meta.isdir):
            continue
        tree_key = key[len(prefix) :]
        tree.add(tree_key, entry.meta, entry.hash_info)
        tree_meta.size += (entry.meta.size if entry.meta else 0) or 0
        tree_meta.nfiles += 1
    tree.digest(name=name)
    return tree_meta, tree


def _save_dir_entry(
    index: "BaseDataIndex",
    key: "DataIndexKey",
    odb: Optional["HashFileDB"] = None,
) -> None:
    from dvc_data.hashfile.db import add_update_tree

    from .index import StorageKeyError

    entry = index[key]

    try:
        cache = odb or index.storage_map.get_cache_odb(entry)
    except StorageKeyError:
        return

    assert cache
    meta, tree = build_tree(index, key)
    tree = add_update_tree(cache, tree)
    entry.meta = meta
    entry.hash_info = tree.hash_info
    assert tree.hash_info.name
    assert tree.hash_info.value
    setattr(entry.meta, tree.hash_info.name, tree.hash_info.value)


if TYPE_CHECKING:
    _ODBMap = dict["HashFileDB", "_FSMap"]
    _FSMap = dict["FileSystem", list[tuple[str, str]]]


def save(
    index: "BaseDataIndex",
    odb: Optional["HashFileDB"] = None,
    callback: "Callback" = DEFAULT_CALLBACK,
    jobs: Optional[int] = None,
    storage: str = "data",
    **kwargs,
) -> int:
    dir_entries: list[DataIndexKey] = []
    transferred = 0

    odb_map: _ODBMap = {}
    for key, entry in index.iteritems():
        if entry.meta and entry.meta.isdir:
            dir_entries.append(key)
            continue

        try:
            fs, path = index.storage_map.get_storage(entry, storage)
        except ValueError:
            continue

        if entry.hash_info:
            cache = odb or index.storage_map.get_cache_odb(entry)
            assert cache
            assert entry.hash_info.value
            oid = entry.hash_info.value
            if cache not in odb_map:
                odb_map[cache] = defaultdict(list)
            odb_map[cache][fs].append((path, oid))
    for cache, fs_map in odb_map.items():
        for fs, args in fs_map.items():
            paths, oids = zip(*args)
            transferred += cache.add(
                list(paths),
                fs,
                list(oids),
                callback=callback,
                batch_size=jobs,
                **kwargs,
            )

    for key in dir_entries:
        _save_dir_entry(index, key, odb=odb)

    return transferred
