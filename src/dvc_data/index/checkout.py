import logging
import os
import stat
from collections import defaultdict
from collections.abc import Collection, Iterable, Iterator
from typing import (
    TYPE_CHECKING,
    Callable,
    Optional,
)

from attrs import define, field
from dvc_objects.fs.generic import transfer
from dvc_objects.fs.local import LocalFileSystem
from dvc_objects.fs.utils import exists as batch_exists
from fsspec.callbacks import DEFAULT_CALLBACK

from dvc_data.callbacks import TqdmCallback
from dvc_data.hashfile.meta import Meta

from .diff import ADD, DELETE, MODIFY, UNCHANGED
from .diff import diff as idiff
from .index import FileStorage, ObjectStorage

if TYPE_CHECKING:
    from dvc_objects.fs.base import AnyFSPath, FileSystem
    from fsspec import Callback

    from dvc_data.hashfile.db import HashFileDB
    from dvc_data.hashfile.hash_info import HashInfo
    from dvc_data.hashfile.state import StateBase

    from .diff import Change
    from .index import BaseDataIndex, DataIndexEntry, DataIndexKey, Storage

logger = logging.getLogger(__name__)


class VersioningNotSupported(Exception):  # noqa: N818
    pass


def _check_versioning(paths: Iterable["AnyFSPath"], fs: "FileSystem"):
    if not fs.version_aware:
        return

    for path in paths:
        try:
            info = fs.info(path)
        except FileNotFoundError:
            continue
        meta = Meta.from_info(info, fs.protocol)
        if meta.version_id in (None, "null"):
            raise VersioningNotSupported(
                f"while uploading {path!r}, "
                "support for versioning could not be detected"
            )


def _delete_files(
    entries: list["DataIndexEntry"],
    path: str,
    fs: "FileSystem",
):
    if not entries:
        return

    fs.remove([fs.join(path, *(entry.key or ())) for entry in entries])


def _cache_objects(
    entries: list["DataIndexEntry"],
    index: Optional["BaseDataIndex"],
) -> list[tuple["HashFileDB", str]]:
    """Find the cache objects that the given workspace entries may link to."""
    if index is None:
        return []

    objects = []
    for entry in entries:
        if not entry.hash_info or not entry.hash_info.value:
            continue
        try:
            storage = index.storage_map[entry.key].cache
        except KeyError:
            continue
        if not isinstance(storage, ObjectStorage):
            continue
        objects.append((storage.odb, storage.odb.oid_to_path(entry.hash_info.value)))
    return objects


def _protect_objects(objects: list[tuple["HashFileDB", str]]) -> None:
    for odb, obj_path in objects:
        if odb.fs.exists(obj_path):
            odb.protect(obj_path)


def _create_files(  # noqa: C901, PLR0912, PLR0913
    entries,
    index: Optional["BaseDataIndex"],
    path: str,
    fs: "FileSystem",
    callback: "Callback" = DEFAULT_CALLBACK,
    update_meta: bool = True,
    jobs: Optional[int] = None,
    storage: str = "cache",
    onerror=None,
    state: Optional["StateBase"] = None,
    links: Optional[list[str]] = None,
):
    if index is None:
        return

    by_storage: dict[Storage, list[tuple[DataIndexEntry, str, str]]] = defaultdict(list)
    for entry in entries:
        dest_path = fs.join(path, *entry.key)
        storage_info = index.storage_map[entry.key]
        storage_obj = getattr(storage_info, storage)

        try:
            src_fs, src_path = storage_obj.get(entry)
        except ValueError as exc:
            logger.warning(
                "No file hash info found for '%s'. It won't be created.",
                dest_path,
            )
            onerror(None, dest_path, exc)
            continue

        by_storage[storage_obj].append((entry, src_path, dest_path))

    for storage_obj, args in by_storage.items():
        if not args:
            continue

        src_fs = storage_obj.fs
        entries, src_paths, dest_paths = zip(*args)

        if links is None and isinstance(storage_obj, ObjectStorage):
            links = storage_obj.odb.cache_types

        transfer(
            src_fs,
            list(src_paths),
            fs,
            list(dest_paths),
            callback=callback,
            batch_size=jobs,
            links=links,
            on_error=onerror,
        )

        _check_versioning(dest_paths, fs)

        if state and isinstance(fs, LocalFileSystem):
            _infos: list[tuple[str, HashInfo, dict]] = []
            for entry, _, dest_path in args:
                if not entry.hash_info:
                    continue
                try:
                    _infos.append((dest_path, entry.hash_info, fs.info(dest_path)))
                except FileNotFoundError:
                    continue
            state.save_many(_infos, fs)

        if update_meta:
            if callback == DEFAULT_CALLBACK:
                cb = callback
            else:
                desc = f"Updating meta for new files in '{path}'"
                cb = TqdmCallback(desc=desc, unit="file")
            with cb:
                infos = fs.info(list(dest_paths), callback=cb, batch_size=jobs)
                for entry, info in zip(entries, infos):
                    entry.meta = Meta.from_info(info, fs.protocol)
                    index.add(entry)

    # FIXME should return new index
    if update_meta:
        for key in list(index.storage_map.keys()):
            index.storage_map.add_data(
                FileStorage(
                    key,
                    fs,
                    fs.join(path, *key),
                )
            )


def _delete_dirs(entries, path, fs):
    reversed_by_key = sorted(entries, key=lambda entry: entry.key, reverse=True)
    for entry in reversed_by_key:
        try:
            fs.rmdir(fs.join(path, *entry.key))
        except OSError:
            pass


def _create_dirs(entries, path, fs):
    for entry in entries:
        fs.makedirs(fs.join(path, *entry.key), exist_ok=True)


def _chmod_files(entries, path, fs):
    if not isinstance(fs, LocalFileSystem):
        return

    for entry in entries:
        entry_path = fs.join(path, *entry.key)
        mode = os.stat(entry_path).st_mode | stat.S_IEXEC
        try:
            os.chmod(entry_path, mode)
        except OSError:
            logger.debug(
                "failed to chmod '%s' '%s'",
                oct(mode),
                entry_path,
                exc_info=True,
            )


@define
class Diff:
    old: Optional["BaseDataIndex"] = field(default=None)
    new: Optional["BaseDataIndex"] = field(default=None)
    changes: dict["DataIndexKey", "Change"] = field(factory=dict)
    files_delete: list = field(factory=list)
    dirs_delete: list = field(factory=list)
    files_create: list = field(factory=list)
    dirs_create: list = field(factory=list)
    files_chmod: list = field(factory=list)
    dirs_failed: list = field(factory=list)


def _compare(  # noqa: C901, PLR0912
    old,
    new,
    relink: bool = False,
    delete: bool = False,
    callback: "Callback" = DEFAULT_CALLBACK,
    **kwargs,
):
    ret = Diff(old=old, new=new)

    def _add_file_create(entry):
        if entry.meta and entry.meta.isexec:
            ret.files_chmod.append(entry)

        ret.files_create.append(entry)

    def _add_create(entry):
        if entry.meta and entry.meta.isdir:
            ret.dirs_create.append(entry)
            return

        _add_file_create(entry)

    def _add_delete(entry):
        if entry.meta and entry.meta.isdir:
            ret.dirs_delete.append(entry)
            return

        ret.files_delete.append(entry)

    def meta_cmp_key(meta):
        if meta is None:
            return meta
        return (meta.isdir, meta.isexec)

    kwargs.setdefault("meta_cmp_key", meta_cmp_key)

    for change in idiff(
        old,
        new,
        with_unchanged=relink,
        callback=callback,
        **kwargs,
    ):
        if change.typ == ADD:
            _add_create(change.new)
        elif change.typ == DELETE:
            if not delete:
                continue

            _add_delete(change.old)
        elif change.typ == UNCHANGED:
            assert relink

            if not change.old.meta or not change.old.meta.isdir:
                ret.files_delete.append(change.old)

            if not change.new.meta or not change.new.meta.isdir:
                _add_file_create(change.new)

            continue
        elif change.typ == MODIFY:
            old_hi = change.old.hash_info
            new_hi = change.new.hash_info
            old_meta = change.old.meta
            new_meta = change.new.meta
            old_isdir = old_meta.isdir if old_meta is not None else False
            new_isdir = new_meta.isdir if new_meta is not None else False
            old_isexec = old_meta.isexec if old_meta is not None else False
            new_isexec = new_meta.isexec if new_meta is not None else False

            if old_hi != new_hi or old_isdir != new_isdir:
                if old_isdir and new_isdir:
                    # no need to recreate the dir
                    continue

                _add_delete(change.old)
                _add_create(change.new)

            elif old_isexec != new_isexec and not new_isdir:
                ret.files_chmod.append(change.new)
            else:
                continue
        else:
            raise AssertionError

        ret.changes[change.key] = change

    return ret


def compare(
    old,
    new,
    relink: bool = False,
    delete: bool = False,
    callback: "Callback" = DEFAULT_CALLBACK,
    **kwargs,
):
    failed_dirs = set()
    onerror = new.onerror

    def _onerror(entry, exc):
        failed_dirs.add(entry)
        onerror(entry, exc)

    new.onerror = _onerror

    try:
        ret = _compare(
            old, new, relink=relink, delete=delete, callback=callback, **kwargs
        )
    finally:
        new.onerror = onerror

    for entry in failed_dirs:
        try:
            ret.dirs_create.remove(entry)
        except ValueError:
            pass
        ret.changes.pop(entry.key, None)

    ret.dirs_failed = failed_dirs

    return ret


def _onerror_noop(*args, **kwargs):
    pass


def apply(
    diff: "Diff",
    path: str,
    fs: "FileSystem",
    callback: "Callback" = DEFAULT_CALLBACK,
    update_meta: bool = True,
    jobs: Optional[int] = None,
    storage: str = "cache",
    onerror: Optional[Callable] = None,
    state: Optional["StateBase"] = None,
    links: Optional[list[str]] = None,
) -> None:
    if onerror is None:
        onerror = _onerror_noop

    for entry in diff.dirs_failed:
        onerror(None, fs.join(path, *entry.key), None)

    # NOTE: On some filesystems (e.g. NTFS) a hardlink shares its read-only
    # attribute with the cache object. Deleting a protected hardlink has to
    # clear that attribute first, which leaves the cache object writable too,
    # so we protect those objects again after the workspace files are gone.
    deleted_objects = (
        _cache_objects(diff.files_delete, diff.new)
        if isinstance(fs, LocalFileSystem)
        else []
    )
    _delete_files(
        diff.files_delete,
        path,
        fs,
    )
    _protect_objects(deleted_objects)
    _delete_dirs(diff.dirs_delete, path, fs)
    _create_dirs(diff.dirs_create, path, fs)

    _create_files(
        diff.files_create,
        diff.new,
        path,
        fs,
        onerror=onerror,
        jobs=jobs,
        storage=storage,
        callback=callback,
        update_meta=update_meta,
        state=state,
        links=links,
    )

    _chmod_files(diff.files_chmod, path, fs)


def _prune_existing_versions(
    entries: Collection["DataIndexEntry"],
    fs: "FileSystem",
    path: str,
    callback: "Callback" = DEFAULT_CALLBACK,
    jobs: Optional[int] = None,
) -> Iterator["DataIndexEntry"]:
    assert fs.version_aware
    query_vers: dict[str, DataIndexEntry] = {}
    jobs = jobs or fs.jobs

    for entry in entries:
        assert entry.meta
        if entry.meta.version_id is None:
            yield entry
        else:
            entry_path = fs.join(path, *(entry.key or ()))
            assert hasattr(fs, "version_path")
            versioned_path = fs.version_path(entry_path, entry.meta.version_id)
            query_vers[versioned_path] = entry
    for pth, exists in batch_exists(
        fs, query_vers.keys(), batch_size=jobs, callback=callback
    ).items():
        if not exists:
            yield query_vers[pth]
