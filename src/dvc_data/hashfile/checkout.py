import logging
import os
from itertools import chain
from typing import TYPE_CHECKING, Callable, Optional, Union

from dvc_objects.fs.generic import test_links, transfer
from dvc_objects.fs.local import LocalFileSystem
from dvc_objects.fs.system import inode
from fsspec.callbacks import DEFAULT_CALLBACK

from dvc_data.fsutils import _localfs_info

from .build import build
from .diff import ROOT, DiffResult
from .diff import diff as odiff

if TYPE_CHECKING:
    from dvc_objects.fs.base import FileSystem
    from fsspec import Callback

    from ._ignore import Ignore
    from .db import HashFileDB
    from .diff import Change
    from .hash_info import HashInfo
    from .meta import Meta
    from .obj import HashFile
    from .state import StateBase
    from .tree import Tree

logger = logging.getLogger(__name__)


class PromptError(Exception):
    def __init__(self, path: str) -> None:
        self.path = path
        super().__init__(f"unable to remove '{path}' without a confirmation.")


class CheckoutError(Exception):
    def __init__(self, paths: list[str]) -> None:
        self.paths = paths
        super().__init__("Checkout failed")


class LinkError(Exception):
    def __init__(self, path: str) -> None:
        self.path = path
        super().__init__("No possible cache link types for '{path}'.")


def _remove(
    path: str,
    fs: "FileSystem",
    in_cache: bool,
    force: bool = False,
    prompt: Optional[Callable[[str], bool]] = None,
):
    if not force and not in_cache:
        if not fs.exists(path):
            return

        msg = (
            f"file/directory '{path}' is going to be removed. "
            "Are you sure you want to proceed?"
        )

        if prompt is None or not prompt(msg):
            raise PromptError(path)

    try:
        fs.remove(path)
    except FileNotFoundError:
        pass


def _relink(
    link: "Link",
    cache: "HashFileDB",
    cache_info: str,
    fs: "FileSystem",
    path: str,
    in_cache: bool,
    force: bool,
    prompt: Optional[Callable[[str], bool]] = None,
):
    _remove(path, fs, in_cache, force=force, prompt=prompt)
    link(cache, cache_info, fs, path)
    # NOTE: Depending on a file system (e.g. on NTFS), `_remove` might reset
    # read-only permissions in order to delete a hardlink to protected object,
    # which will also reset it for the object itself, making it unprotected,
    # so we need to protect it back.
    cache.protect(cache_info)


def _checkout_file(
    link: "Link",
    path: str,
    fs: "FileSystem",
    change: "Change",
    cache: "HashFileDB",
    force: bool,
    relink: bool = False,
    state: Optional["StateBase"] = None,
    prompt: Optional[Callable[[str], bool]] = None,
):
    """The file is changed we need to checkout a new copy"""
    modified = False

    assert change.new.oid
    assert change.new.oid.value
    cache_path = cache.oid_to_path(change.new.oid.value)
    if change.old.oid:
        if relink:
            old_meta = change.old.meta
            if old_meta is None:
                file_is_copy = fs.iscopy(path)
            else:
                file_is_copy = not old_meta.is_link and old_meta.nlink == 1

            cache_is_copy = cache.cache_types[0] == "copy"
            if file_is_copy and change.new.oid == change.old.oid and cache_is_copy:
                cache.unprotect(path)
            else:
                _relink(
                    link,
                    cache,
                    cache_path,
                    fs,
                    path,
                    change.old.in_cache,
                    force=force,
                    prompt=prompt,
                )
        else:
            modified = True
            _relink(
                link,
                cache,
                cache_path,
                fs,
                path,
                change.old.in_cache,
                force=force,
                prompt=prompt,
            )
    else:
        link(cache, cache_path, fs, path)
        modified = True
    return modified


def _needs_relink(
    path: str,
    cache: "HashFileDB",
    meta: "Meta",
    cache_meta: Optional["Meta"],
    oid: Optional[str],
) -> bool:
    destination = meta.destination
    is_symlink = meta.is_link
    is_hardlink = meta.nlink > 1
    is_copy = not is_symlink and not is_hardlink

    for link_type in cache.cache_types:
        if link_type in ("copy", "reflink") and is_copy:
            return False
        if link_type == "hardlink" and is_hardlink and cache_meta is not None:
            return meta.inode != cache_meta.inode
        if link_type == "symlink" and is_symlink and destination and oid:
            if os.name == "nt":
                # See: https://github.com/python/cpython/issues/87123
                # https://github.com/jaraco/path/blob/e03580edf6cfec719890599010e0b164d06af50f/path/__init__.py#L1361
                destination = destination.removeprefix("\\\\?\\")
            return destination != cache.oid_to_path(oid)
    return True


def _determine_files_to_relink(
    diff: DiffResult, path: str, fs: "FileSystem", cache: "HashFileDB"
) -> None:
    modified = diff.modified
    if not isinstance(fs, LocalFileSystem) or not isinstance(cache.fs, LocalFileSystem):
        modified.extend(diff.unchanged)
        return

    path_join = fs.sep.join
    mappend = modified.append
    for change in diff.unchanged:
        old = change.old
        new = change.new
        if new.oid and new.oid.isdir:
            continue

        old_meta = old.meta
        if old_meta is None:
            mappend(change)
            continue

        p = path_join((path, *old.key))
        oid = new.oid
        oid_str = oid.value if oid is not None else None
        if _needs_relink(p, cache, old_meta, new.cache_meta, oid_str):
            mappend(change)


def _diff(
    path: str,
    fs: "FileSystem",
    obj: Union["HashFile", "Tree"],
    cache: "HashFileDB",
    relink: bool = False,
    ignore: Optional["Ignore"] = None,
    old: Union["HashFile", "Tree", None] = None,
):
    if old is None:
        try:
            name = (
                obj.hash_info.name
                if obj and obj.hash_info and obj.hash_info.name
                else cache.hash_name
            )
            _, _, old = build(
                cache,
                path,
                fs,
                name,
                dry_run=True,
                ignore=ignore,
            )
        except FileNotFoundError:
            pass

    diff = odiff(old, obj, cache)
    if relink:
        _determine_files_to_relink(diff, path, fs, cache)
    else:
        for change in diff.unchanged:
            if not change.new.in_cache and not (
                change.new.oid and change.new.oid.isdir
            ):
                diff.modified.append(change)
    return diff


class Link:
    def __init__(
        self, links: Optional[list[str]], callback: "Callback" = DEFAULT_CALLBACK
    ):
        self._links = links
        self._callback = callback
        self._created_dirs: set[str] = set()

    def __call__(
        self, cache: "HashFileDB", from_path: str, to_fs: "FileSystem", to_path: str
    ):
        parent = to_fs.parent(to_path)
        if parent not in self._created_dirs:
            to_fs.makedirs(parent)
            self._created_dirs.add(parent)

        try:
            transfer(
                cache.fs,
                from_path,
                to_fs,
                to_path,
                links=self._links,
                callback=self._callback,
            )
        except FileNotFoundError as exc:
            raise CheckoutError([to_path]) from exc
        except OSError as exc:
            raise LinkError(to_path) from exc


def _save_link(
    path: str,
    fs: "FileSystem",
    diff: DiffResult,
    updated_mtimes: dict[str, float],
    state: "StateBase",
) -> None:
    if not isinstance(fs, LocalFileSystem):
        return

    from .utils import _get_mtime_from_changes

    mtime = _get_mtime_from_changes(path, fs, diff, updated_mtimes)
    ino = inode(path)
    return state.set_link(path, ino, mtime)


def _checkout(  # noqa: C901
    diff: DiffResult,
    path: str,
    fs: "FileSystem",
    cache: "HashFileDB",
    force: bool = False,
    progress_callback: "Callback" = DEFAULT_CALLBACK,
    relink: bool = False,
    state: Optional["StateBase"] = None,
    prompt: Optional[Callable[[str], bool]] = None,
):
    if not diff:
        if relink and state is not None:
            _save_link(path, fs, diff, {}, state)
        return

    links = test_links(cache.cache_types, cache.fs, cache.path, fs, path)
    if not links:
        raise LinkError(path)

    progress_callback.set_size(sum(diff.stats.values()))
    link = Link(links, callback=progress_callback)
    for change in diff.deleted:
        entry_path = fs.join(path, *change.old.key) if change.old.key != ROOT else path
        _remove(entry_path, fs, change.old.in_cache, force=force, prompt=prompt)

    failed = []
    hashes_to_update: list[tuple[str, HashInfo, dict]] = []
    is_local_fs = isinstance(fs, LocalFileSystem)
    updated_mtimes = {}
    for change in chain(diff.added, diff.modified):
        entry_path = fs.join(path, *change.new.key) if change.new.key != ROOT else path
        assert change.new.oid
        if change.new.oid.isdir:
            fs.makedirs(entry_path)
            continue

        try:
            _checkout_file(
                link,
                entry_path,
                fs,
                change,
                cache,
                force,
                relink,
                state=state,
                prompt=prompt,
            )
        except CheckoutError as exc:
            failed.extend(exc.paths)
        else:
            if is_local_fs:
                info = _localfs_info(entry_path)
                hashes_to_update.append((entry_path, change.new.oid, info))
                updated_mtimes[entry_path] = info["mtime"]

    if state is not None:
        state.save_many(hashes_to_update, fs)
        _save_link(path, fs, diff, updated_mtimes, state)

    if failed:
        raise CheckoutError(failed)


def checkout(  # noqa: PLR0913, PLR0917
    path: str,
    fs: "FileSystem",
    obj: Union["HashFile", "Tree"],
    cache: "HashFileDB",
    force: bool = False,
    progress_callback: "Callback" = DEFAULT_CALLBACK,
    relink: bool = False,
    quiet: bool = False,
    ignore: Optional["Ignore"] = None,
    state: Optional["StateBase"] = None,
    prompt: Optional[Callable[[str], bool]] = None,
    old: Union["HashFile", "Tree", None] = None,
    checksum_jobs: Optional[int] = None,
):
    # if protocol(path) not in ["local", cache.fs.protocol]:
    #    raise NotImplementedError

    diff = _diff(
        path,
        fs,
        obj,
        cache,
        relink=relink,
        ignore=ignore,
        old=old,
    )

    failed = []
    if not obj:
        if not quiet:
            logger.warning(
                "No file hash info found for '%s'. It won't be created.",
                path,
            )
        failed.append(path)

    try:
        _checkout(
            diff,
            path,
            fs,
            cache,
            force=force,
            progress_callback=progress_callback,
            relink=relink,
            state=state,
            prompt=prompt,
        )
    except CheckoutError as exc:
        failed.extend(exc.paths)

    if failed or not diff:
        if progress_callback and obj:
            progress_callback.relative_update(len(obj))
        if failed:
            raise CheckoutError(failed)
        return

    return bool(diff) and not relink
