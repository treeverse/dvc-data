from collections.abc import Iterable
from typing import TYPE_CHECKING, Optional

if TYPE_CHECKING:
    from .db import HashFileDB
    from .hash_info import HashInfo


def is_dir_hash(_hash):
    from .hash_info import HASH_DIR_SUFFIX

    return _hash.endswith(HASH_DIR_SUFFIX)


def _get_used_hashes(
    odb: "HashFileDB",
    used: Iterable["HashInfo"],
    shallow: bool = True,
    cache_odb: Optional["HashFileDB"] = None,
) -> set[str]:
    """Recursively collects all used hash values from a given set of HashInfos."""
    from .tree import Tree

    if not cache_odb:
        cache_odb = odb

    used_hashes = set()
    for hash_info in used:
        if hash_info.name != odb.hash_name or not hash_info.value:
            continue
        used_hashes.add(hash_info.value)
        if hash_info.isdir and not shallow:
            tree = Tree.load(cache_odb, hash_info)
            used_hashes.update(
                entry.hash_info.value for _, entry in tree if entry.hash_info.value
            )
    return used_hashes


def iter_garbage(
    odb: "HashFileDB",
    used: Iterable["HashInfo"],
    jobs: Optional[int] = None,
    shallow: bool = True,
    cache_odb: Optional["HashFileDB"] = None,
) -> Iterable[str]:
    """
    Yields garbage object hashes by comparing all objects in the ODB
    against the set of used hashes.
    """
    from dvc_objects.errors import ObjectDBPermissionError

    from ._progress import QueryingProgress

    if odb.read_only:
        raise ObjectDBPermissionError("Cannot gc read-only ODB")

    used_hashes = _get_used_hashes(odb, used, shallow=shallow, cache_odb=cache_odb)
    for hash_ in QueryingProgress(odb.all(jobs), name=odb.path):
        if hash_ not in used_hashes:
            yield hash_


def gc(
    odb: "HashFileDB",
    used: Iterable["HashInfo"],
    jobs: Optional[int] = None,
    cache_odb: Optional["HashFileDB"] = None,
    shallow: bool = True,
    dry: bool = False,
):
    garbage = iter_garbage(odb, used, jobs=jobs, shallow=shallow, cache_odb=cache_odb)
    num_removed = 0

    dir_paths = []
    file_paths = []
    for hash_ in garbage:
        path = odb.oid_to_path(hash_)
        if is_dir_hash(hash_):
            # backward compatibility
            odb._remove_unpacked_dir(hash_)
            dir_paths.append(path)
        else:
            file_paths.append(path)

    for paths in (dir_paths, file_paths):
        if paths:
            num_removed += len(paths)
            if not dry:
                odb.fs.remove(paths)

    return num_removed
