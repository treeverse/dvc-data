import logging
import os
from abc import ABC, abstractmethod
from collections.abc import Iterable, Iterator
from typing import TYPE_CHECKING

from dvc_objects.errors import ObjectDBError

if TYPE_CHECKING:
    from dvc_objects.fs.base import AnyFSPath

logger = logging.getLogger(__name__)


class ObjectDBIndexBase(ABC):
    @abstractmethod
    def __init__(
        self,
        tmp_dir: "AnyFSPath",
        name: str,
    ) -> None:
        pass

    @abstractmethod
    def close(self) -> None:
        pass

    @abstractmethod
    def __iter__(self) -> Iterator[str]:
        pass

    @abstractmethod
    def __contains__(self, hash_: str) -> bool:
        pass

    def hashes(self) -> Iterator[str]:
        return iter(self)

    @abstractmethod
    def dir_hashes(self) -> Iterator[str]:
        pass

    @abstractmethod
    def clear(self) -> None:
        pass

    @abstractmethod
    def update(self, dir_hashes: Iterable[str], file_hashes: Iterable[str]) -> None:
        pass

    @abstractmethod
    def intersection(self, hashes: set[str]) -> Iterator[str]:
        pass


class ObjectDBIndexNoop(ObjectDBIndexBase):
    """No-op class for ODBs which are not indexed."""

    def __init__(
        self,
        tmp_dir: "AnyFSPath",
        name: str,
    ) -> None:
        pass

    def close(self) -> None:
        pass

    def __iter__(self) -> Iterator[str]:
        return iter([])

    def __contains__(self, hash_: str) -> bool:
        return False

    def dir_hashes(self) -> Iterator[str]:
        yield from []

    def clear(self) -> None:
        pass

    def update(self, dir_hashes: Iterable[str], file_hashes: Iterable[str]) -> None:
        pass

    def intersection(self, hashes: set[str]) -> Iterator[str]:
        yield from []


class ObjectDBIndex(ObjectDBIndexBase):
    """Class for indexing hashes in an ODB."""

    INDEX_SUFFIX = ".idx"
    INDEX_DIR = "index"

    def __init__(
        self,
        tmp_dir: "AnyFSPath",
        name: str,
    ) -> None:
        from dvc_objects.fs import LocalFileSystem

        from dvc_data.hashfile.cache import Cache, Index

        self.index_dir = os.path.join(tmp_dir, self.INDEX_DIR, name)
        self.fs = LocalFileSystem()
        self.fs.makedirs(self.index_dir, exist_ok=True)
        self._cache = Cache(self.index_dir, eviction_policy="none", type="index")
        self.index = Index.fromcache(self._cache)

    def close(self) -> None:
        return self._cache.close()

    def __iter__(self) -> Iterator[str]:
        return iter(self.index)

    def __contains__(self, hash_: str) -> bool:
        return hash_ in self.index

    def dir_hashes(self) -> Iterator[str]:
        """Iterate over .dir hashes stored in the index."""
        # Read via get() rather than items(): an entry written by an older,
        # pickle-serializing dvc-data is dropped as a miss, and iterating
        # items() would race that eviction and raise KeyError.
        for hash_ in list(self.index):
            if self.index.get(hash_):
                yield hash_

    def clear(self) -> None:
        """Clear this index (to force re-indexing later)."""
        from dvc_data.hashfile.cache import Timeout

        try:
            self.index.clear()
        except Timeout as exc:
            raise ObjectDBError("Failed to clear ODB index") from exc

    def update(self, dir_hashes: Iterable[str], file_hashes: Iterable[str]) -> None:
        """Update this index, adding the specified hashes."""
        from dvc_data.hashfile.cache import Timeout

        try:
            with self.index.transact():
                for hash_ in dir_hashes:
                    self.index[hash_] = True
            with self.index.transact():
                for hash_ in file_hashes:
                    self.index[hash_] = False
        except Timeout as exc:
            raise ObjectDBError("Failed to update ODB index") from exc

    def intersection(self, hashes: set[str]) -> Iterator[str]:
        """Iterate over values from `hashes` which exist in the index."""
        yield from hashes.intersection(self.index.keys())
