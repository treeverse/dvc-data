import logging
from contextlib import closing
from functools import partial
from typing import TYPE_CHECKING, Optional

from dvc_objects.fs.local import LocalFileSystem
from fsspec.callbacks import DEFAULT_CALLBACK

from dvc_data.callbacks import TqdmCallback
from dvc_data.hashfile.db import get_index
from dvc_data.hashfile.meta import Meta
from dvc_data.hashfile.transfer import transfer

from .build import build
from .checkout import apply, compare
from .collect import collect  # noqa: F401
from .index import DataIndex, ObjectStorage
from .save import md5, save

if TYPE_CHECKING:
    from fsspec import Callback

    from dvc_data.hashfile.status import CompareStatusResult

    from .index import DataIndexKey

logger = logging.getLogger(__name__)


def _log_missing(status: "CompareStatusResult"):
    if status.missing:
        missing_desc = "\n".join(f"{hash_info}" for hash_info in status.missing)
        logger.warning(
            "Some of the cache files do not exist neither locally "
            "nor on remote. Missing cache files:\n%s",
            missing_desc,
        )


def _onerror(data, cache, failed_keys, src_path, dest_path, exc):
    if not isinstance(exc, FileNotFoundError) or data.fs.exists(src_path):
        failed_keys.add(cache.fs.relparts(dest_path, cache.path))

    logger.debug(
        "failed to create '%s' from '%s'",
        src_path,
        dest_path,
        exc_info=True,
    )


def _filter_changed(index):
    ret = DataIndex()
    ret.storage_map = index.storage_map

    for _, entry in index.items():
        if entry.meta and entry.meta.isdir:
            ret.add(entry)
            continue

        if not entry.meta or entry.meta.version_id:
            ret.add(entry)
            continue

        try:
            data_fs, data_path = index.storage_map.get_data(entry)
        except ValueError:
            continue

        try:
            info = data_fs.info(data_path)
        except FileNotFoundError:
            continue

        if getattr(data_fs, "immutable", None):
            ret.add(entry)
            continue

        meta = Meta.from_info(info, data_fs.protocol)
        old = getattr(entry.meta, data_fs.PARAM_CHECKSUM, None) if entry.meta else None
        new = getattr(meta, data_fs.PARAM_CHECKSUM, None)

        if old and new is None and isinstance(data_fs, LocalFileSystem):
            # NOTE: temporary ugly hack to handle local sources where
            # the only thing we currently have is md5.
            from dvc_data.hashfile.hash import hash_file

            _, hi = hash_file(data_path, data_fs, "md5")
            new = hi.value

        if old and new and old == new:
            ret.add(entry)

    return ret


def fetch(
    idxs,
    callback: "Callback" = DEFAULT_CALLBACK,
    jobs: Optional[int] = None,
):
    fetched, failed = 0, 0
    for fs_index in idxs:
        data = fs_index.storage_map[()].data
        cache = fs_index.storage_map[()].cache

        if callback != DEFAULT_CALLBACK:
            cb = TqdmCallback(
                unit="file",
                total=len(fs_index),
                desc=f"Fetching from {data.fs.protocol}",
            )
        else:
            cb = callback

        try:
            # NOTE: make sure there are no auth errors
            data.fs.exists(data.path)
        except Exception:
            failed += len(fs_index)
            logger.exception(
                "failed to connect to %s (%s)", data.fs.protocol, data.path
            )
            continue

        with cb:
            if isinstance(cache, ObjectStorage) and isinstance(data, ObjectStorage):
                with closing(get_index(data.odb)) as src_index:
                    result = transfer(
                        data.odb,
                        cache.odb,
                        [
                            entry.hash_info
                            for _, entry in fs_index.iteritems()
                            if entry.hash_info
                        ],
                        jobs=jobs,
                        src_index=src_index,
                        cache_odb=cache.odb,
                        verify=data.odb.verify,
                        validate_status=_log_missing,
                        callback=cb,
                    )
                fetched += len(result.transferred)
                failed += len(result.failed)
            elif isinstance(cache, ObjectStorage):
                updated = md5(fs_index)

                def _on_error(failed, oid, exc):
                    if isinstance(exc, FileNotFoundError):
                        return
                    failed += 1
                    logger.debug(
                        "failed to transfer '%s'",
                        oid,
                        exc_info=True,
                    )

                fetched += save(
                    updated,
                    jobs=jobs,
                    callback=cb,
                    on_error=partial(_on_error, failed),
                )
            else:
                old = build(cache.path, cache.fs)
                filtered = _filter_changed(fs_index)
                diff = compare(old, filtered)
                cache.fs.makedirs(cache.fs.parent(cache.path), exist_ok=True)

                failed_keys: set[DataIndexKey] = set()
                apply(
                    diff,
                    cache.path,
                    cache.fs,
                    update_meta=False,
                    storage="data",
                    jobs=jobs,
                    callback=cb,
                    onerror=partial(_onerror, data, cache, failed_keys),
                )

                added_keys = {entry.key for entry in diff.files_create}
                fetched += len(added_keys - failed_keys)
                failed += len(failed_keys)

    return fetched, failed
