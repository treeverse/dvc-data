import json
import os
from collections.abc import Iterable, Iterator, Sequence
from typing import Any, ClassVar, Optional

import pysciqlop_cache
from pysciqlop_cache import Timeout  # noqa: F401

from dvc_data.compat import batched


class DiskError(Exception):
    def __init__(self, directory: str, type: str) -> None:  # noqa: A002
        self.directory = directory
        self.type = type
        super().__init__(f"Could not open disk '{type}' in {directory}")


class _Serializer:
    """Base of the value encodings. None of them can run code on load
    (CVE-2025-69872). An entry that cannot be decoded raises DiskError, so dvc
    tells the user to remove the cache directory, as it did for bad pickles."""

    name: str

    def __init__(self, directory: str, type: str) -> None:  # noqa: A002
        self._directory = directory
        self._type = type

    def loads(self, data: "bytes | memoryview") -> Any:
        try:
            return self._decode(str(data, "utf-8"))
        except ValueError as e:  # UnicodeDecodeError and JSONDecodeError
            raise DiskError(self._directory, type=self._type) from e

    def dumps(self, value: Any) -> bytes:
        raise NotImplementedError

    def _decode(self, text: str) -> Any:
        raise NotImplementedError


class _Text(_Serializer):
    """str values, stored as their UTF-8 bytes."""

    name = "dvc-text"

    def dumps(self, value: str) -> bytes:
        return value.encode()

    def _decode(self, text: str) -> str:
        return text


class _Json(_Serializer):
    """JSON values. JSON has no tuple type: arrays come back as tuples."""

    name = "dvc-json"
    # json.dumps() with any keyword builds a new encoder on every call.
    _encode = json.JSONEncoder(separators=(",", ":")).encode

    def dumps(self, value: Any) -> bytes:
        return self._encode(value).encode()

    def _decode(self, text: str) -> Any:
        value = json.loads(text)
        return tuple(value) if isinstance(value, list) else value


class Cache(pysciqlop_cache.Cache):
    def __init__(
        self,
        directory: Optional[str] = None,
        timeout: int = 60,
        type: Optional[str] = None,  # noqa: A002
        **settings: Any,
    ) -> None:
        directory = os.fspath(directory) if directory is not None else None
        self._type = type or os.path.basename(directory or "")
        serializer = _Json(directory or "", self._type)
        super().__init__(directory, serializer=serializer, timeout=timeout, **settings)


class Index(pysciqlop_cache.Index):
    SERIALIZER: ClassVar[type[_Serializer]] = _Json

    def __init__(self, directory: str, type: Optional[str] = None) -> None:  # noqa: A002
        directory = os.fspath(directory)
        self._type = type or os.path.basename(directory)
        super().__init__(directory, serializer=self.SERIALIZER(directory, self._type))


class HashesCache(Index):
    """A bare key-value store of the JSON text dvc builds: hashes need no expiry,
    LRU or tags, and the text is stored as is."""

    SERIALIZER = _Text
    BATCH_SIZE: ClassVar[int] = 999
    SUPPORTS_UPSERT: ClassVar[bool] = True  # kept for callers; every set is an upsert

    # dvc's API: (key, value) pairs in the order asked, not the base class's dict.
    def get_many(  # type: ignore[override]
        self, keys: Iterable[str], default=None
    ) -> Iterator[tuple[str, Optional[str]]]:
        for chunk in batched(keys, self.BATCH_SIZE):
            found = super().get_many(chunk)
            for key in chunk:
                yield key, found.get(key, default)

    def set_many(self, items: Sequence[tuple[str, str]], retry: bool = False) -> None:
        if items:
            super().set_many(items)

    def is_empty(self) -> bool:
        return len(self) == 0
