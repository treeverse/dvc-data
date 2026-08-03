import json
import os
import os.path as op
import pickle
import sqlite3
from collections.abc import Iterable, Iterator, Sequence
from functools import wraps
from itertools import zip_longest
from typing import Any, ClassVar, Literal, Optional

import diskcache
from diskcache import Disk as _Disk
from diskcache import (
    Index,  # noqa: F401
    Timeout,  # noqa: F401
)
from diskcache.core import MODE_PICKLE, UNKNOWN

from dvc_data.compat import batched

# Protocol 2+ pickles start with the PROTO opcode; no JSON encoding can.
PICKLE_PROTO_OPCODE = b"\x80"

# diskcache stores SQLite-native values as-is; everything else it pickles.
_SQLITE_INT_MIN = -9223372036854775808
_SQLITE_INT_MAX = 9223372036854775807


def _stored_raw(value: Any, min_file_size: int) -> bool:
    """Whether diskcache would store `value` without pickling it.

    Mirrors the type dispatch in `diskcache.Disk.store`, which uses exact type
    checks -- note that `bool` is therefore *not* covered by the `int` case.
    """
    type_value = type(value)
    if type_value is bytes:
        return True
    if type_value is str:
        return len(value) < min_file_size
    if type_value is float:
        return True
    return type_value is int and _SQLITE_INT_MIN <= value <= _SQLITE_INT_MAX


class DiskError(Exception):
    def __init__(self, directory: str, type: str) -> None:  # noqa: A002
        self.directory = directory
        self.type = type
        super().__init__(f"Could not open disk '{type}' in {directory}")


class LegacyPickleError(Exception):
    """A cache entry was written by an older, pickle-serializing dvc-data."""


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


class JSONDisk(Disk):
    """Serialize values as JSON rather than pickle.

    diskcache pickles any value that is not a str, int, float, or bytes, and
    unpickles it on read. That makes the cache directory a code-execution
    surface: anything able to write into it can hand a poisoned payload to the
    next reader (CVE-2025-69872 / GHSA-w8v5-vhqr-4h9v, unfixed upstream --
    5.6.3 is the newest release and both proposed fixes were declined).

    dvc-data does not need pickle's expressiveness. Every value it caches is a
    dict, bool, tuple of numbers, or an already-JSON-encoded string, so JSON
    covers the whole domain with no code-execution primitive on read.

    Only values the base class would have pickled are re-encoded; str, int,
    float, and bytes keep their existing raw storage, so `HashesCache` -- which
    writes through this disk but reads back with raw SQL -- is untouched. Keys
    are likewise left to the base class, which stores dvc-data's string keys
    raw and is therefore already pickle-free.

    JSON payloads reuse the MODE_PICKLE slot, so entries written by an older
    dvc-data are still recognised. The two are told apart by content: a
    protocol-2+ pickle starts with the PROTO opcode (0x80), which no JSON
    encoding can begin with.
    """

    def store(self, value, read, key=UNKNOWN):
        if read or _stored_raw(value, self.min_file_size):
            # A file-like value is streamed verbatim; str/int/float/bytes are
            # stored raw. Neither is pickled, so leave both to the base class.
            return super().store(value, read, key=key)

        data = json.dumps(value, separators=(",", ":"), sort_keys=True).encode()
        size, _, filename, db_value = super().store(data, False, key=key)
        # Reuse the MODE_PICKLE slot so `fetch` knows to decode the payload.
        return size, MODE_PICKLE, filename, db_value

    def fetch(self, mode, filename, value, read):
        if mode != MODE_PICKLE:
            return super().fetch(mode, filename, value, read)

        if value is None:
            with open(op.join(self._directory, filename), "rb") as reader:
                data = reader.read()
        else:
            data = bytes(value)

        if data[:1] == PICKLE_PROTO_OPCODE:
            # Written by a pre-JSON dvc-data. Refuse to unpickle it; Cache
            # turns this into a miss so the entry is recomputed.
            raise LegacyPickleError
        return json.loads(data)


class Cache(diskcache.Cache):
    """Extended to handle pickle errors and use a constant pickle protocol."""

    def __init__(
        self,
        directory: Optional[str] = None,
        timeout: int = 60,
        disk: _Disk = JSONDisk,
        type: Optional[str] = None,  # noqa: A002
        **settings: Any,
    ) -> None:
        settings.setdefault("disk_pickle_protocol", 4)
        settings.setdefault("cull_limit", 0)
        super().__init__(directory=directory, timeout=timeout, disk=disk, **settings)
        self.disk._type = self._type = type or os.path.basename(self.directory)

    def __getstate__(self):
        return (*super().__getstate__(), self._type)

    def _evict_legacy(self, key) -> None:
        try:
            super().__delitem__(key, retry=True)
        except KeyError:
            pass

    def get(
        self,
        key,
        default=None,
        read=False,
        expire_time=False,
        tag=False,
        retry=False,
    ):
        """Return the value for `key`, treating legacy pickled entries as misses.

        These caches all live under `tmp_dir` and are regenerable, so dropping
        an entry costs a recomputation rather than data.
        """
        try:
            return super().get(
                key,
                default=default,
                read=read,
                expire_time=expire_time,
                tag=tag,
                retry=retry,
            )
        except LegacyPickleError:
            self._evict_legacy(key)
            if expire_time and tag:
                return default, None, None
            if expire_time or tag:
                return default, None
            return default

    def __getitem__(self, key):
        try:
            return super().__getitem__(key)
        except LegacyPickleError:
            self._evict_legacy(key)
            raise KeyError(key) from None

    def __contains__(self, key) -> bool:
        # `in` must agree with reads: a legacy entry is not readable.
        try:
            return super().__contains__(key)
        except LegacyPickleError:
            self._evict_legacy(key)
            return False


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
        self, key, default=None, read=False, expire_time=False, tag=False, retry=False
    ):
        cursor = self._sql("SELECT value FROM Cache WHERE key = ? and raw = 1", (key,))
        if rows := cursor.fetchall():
            return rows[0][0]
        return default
