import os
import pickle
import sqlite3
from collections.abc import Iterable, Iterator, Sequence
from functools import wraps
from itertools import zip_longest
from typing import Any, ClassVar, Literal, Optional

import diskcache_community as diskcache
from diskcache_community import (
    Index,  # noqa: F401
    Timeout,  # noqa: F401
)
from diskcache_community import SafeDisk as _Disk

from dvc_data.compat import batched


class DiskError(Exception):
    def __init__(self, directory: str, type: str) -> None:  # noqa: A002
        self.directory = directory
        self.type = type
        super().__init__(f"Could not open disk '{type}' in {directory}")


def translate_pickle_error(fn):
    @wraps(fn)
    def wrapped(self, *args, **kwargs):
        try:
            return fn(self, *args, **kwargs)
        except (pickle.PickleError, ValueError) as e:
            if isinstance(e, ValueError) and "pickle protocol" not in str(e):
                raise

            raise DiskError(self._directory, type=self._type) from e

    return wrapped


class Disk(_Disk):
    """Reraise pickle-related errors as DiskError."""

    # we need type to differentiate cache for better error messages
    _type: str

    put = translate_pickle_error(_Disk.put)
    get = translate_pickle_error(_Disk.get)
    store = translate_pickle_error(_Disk.store)
    fetch = translate_pickle_error(_Disk.fetch)


class Cache(diskcache.Cache):
    """Extended to handle pickle errors and use a constant pickle protocol."""

    def __init__(
        self,
        directory: Optional[str] = None,
        timeout: int = 60,
        disk: type[_Disk] = Disk,
        type: Optional[str] = None,  # noqa: A002
        **settings: Any,
    ) -> None:
        settings.setdefault("disk_pickle_protocol", 4)
        settings.setdefault("cull_limit", 0)
        super().__init__(directory=directory, timeout=timeout, disk=disk, **settings)
        self.disk._type = self._type = type or os.path.basename(self.directory)  # type: ignore[attr-defined]

    def __getstate__(self):
        return (*super().__getstate__(), self._type)


class HashesCache(Cache):
    SUPPORTS_UPSERT = sqlite3.sqlite_version_info >= (3, 24, 0)
    SQLITE_MAX_VARIABLE_NUMBER: ClassVar[Literal[999]] = 999
    """The maximum number of host parameters is 999 for SQLite versions prior to 3.32.0
    (2020-05-22) or 32766 for SQLite versions after 3.32.0.

    Increasing this number does not yield any performance improvement, so we leave it at
    the old default.
    """

    def get_many(
        self, keys: Iterable[str], default=None
    ) -> Iterator[tuple[str, Optional[str]]]:
        if self.is_empty():
            yield from zip_longest(keys, [])
            return

        for chunk in batched(keys, self.SQLITE_MAX_VARIABLE_NUMBER):
            params = ", ".join("?" * len(chunk))
            query = f"SELECT key, value FROM Cache WHERE key IN ({params}) and raw = 1"  # noqa: S608
            d = dict(self._sql(query, chunk).fetchall())
            for key in chunk:
                yield key, d.get(key, default)

    def set_many(self, items: Sequence[tuple[str, str]], retry: bool = False) -> None:
        if not items:
            return

        if self.SUPPORTS_UPSERT:
            query = (
                "INSERT INTO Cache("
                " key, raw, store_time, expire_time, access_time,"
                " tag, mode, filename, value"
                ") VALUES (?, 1, 0, null, 0, null, 1, null, ?)"
                " ON CONFLICT(key, raw) DO UPDATE SET value = excluded.value"
            )
        else:
            query = (
                "INSERT OR REPLACE INTO Cache("
                " key, raw, store_time, expire_time, access_time,"
                " tag, mode, filename, value"
                ") VALUES (?, 1, 0, null, 0, null, 1, null, ?)"
            )
        with self.transact(retry):
            self._con.executemany(query, items)

    def is_empty(self) -> bool:
        res = self._sql("SELECT EXISTS (SELECT 1 FROM Cache)")
        ((exists,),) = res
        return exists == 0

    def get(
        self,
        key,
        default=None,
        read=False,
        expire_time=False,
        tag=False,
        retry=False,
        store_time=False,
    ):
        cursor = self._sql("SELECT value FROM Cache WHERE key = ? and raw = 1", (key,))
        if rows := cursor.fetchall():
            return rows[0][0]
        return default
