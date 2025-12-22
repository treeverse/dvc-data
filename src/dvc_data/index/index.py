import errno
import logging
import os
from abc import ABC, abstractmethod
from collections import defaultdict
from collections.abc import Iterator, MutableMapping
from typing import TYPE_CHECKING, Any, Callable, Optional, cast

import attrs
from fsspec import Callback
from fsspec.callbacks import DEFAULT_CALLBACK
from sqltrie import JSONTrie, PyGTrie, ShortKeyError, SQLiteTrie

from dvc_data.compat import cached_property
from dvc_data.hashfile.hash_info import HashInfo
from dvc_data.hashfile.meta import Meta
from dvc_data.hashfile.tree import Tree

if TYPE_CHECKING:
    from dvc_objects.fs.base import FileSystem

    from dvc_data.hashfile.db import HashFileDB


logger = logging.getLogger(__name__)

DataIndexKey = tuple[str, ...]


@attrs.define(unsafe_hash=True)
class DataIndexEntry:
    key: Optional[DataIndexKey] = None
    meta: Optional["Meta"] = None
    hash_info: Optional["HashInfo"] = None

    loaded: Optional[bool] = None

    @property
    def isdir(self) -> bool:
        if self.meta:
            return self.meta.isdir

        return False

    @classmethod
    def from_dict(cls, d: dict[str, dict]) -> "DataIndexEntry":
        ret = cls()

        meta = d.get("meta")
        if meta:
            ret.meta = Meta.from_dict(meta)

        hash_info = d.get("hash_info")
        if hash_info:
            ret.hash_info = HashInfo.from_dict(hash_info)

        ret.loaded = cast("bool", d["loaded"])

        return ret

    def to_dict(self) -> dict[str, Any]:
        ret: dict[str, Any] = {}

        if self.meta:
            ret["meta"] = self.meta.to_dict()

        if self.hash_info:
            ret["hash_info"] = self.hash_info.to_dict()

        ret["loaded"] = self.loaded

        return ret

    @property
    def size(self) -> Optional[int]:
        if self.meta is None:
            return None

        return self.meta.size


class DataIndexTrie(JSONTrie):
    def __init__(self, *args, **kwargs):
        self._cache = {}
        super().__init__(*args, **kwargs)

    @cached_property
    def _trie(self):
        return SQLiteTrie()

    @classmethod
    def open(cls, path):
        ret = cls()
        ret._trie = SQLiteTrie.open(path)
        return ret

    def _load(self, key, value):
        try:
            return self._cache[key]
        except KeyError:
            pass
        if value is None:
            return None

        d = super()._load(key, value)
        assert isinstance(d, dict)
        entry = DataIndexEntry.from_dict(d)
        entry.key = key
        return entry

    def _dump(self, key, value):
        if key not in self._cache:
            self._cache[key] = value
        if value is None:
            return None
        return super()._dump(key, value.to_dict())

    def __setitem__(self, key, value):
        self._cache.pop(key, None)
        super().__setitem__(key, value)

    def __delitem__(self, key):
        self._cache.pop(key, None)
        super().__delitem__(key)

    def delete_node(self, key):
        self._cache.pop(key, None)
        super().delete_node(key)

    def close(self):
        self._cache = {}
        super().close()


class Storage(ABC):
    def __init__(self, key: "DataIndexKey", read_only: bool = False):
        self.key = key
        self.read_only = read_only

    @property
    @abstractmethod
    def fs(self):
        pass

    @property
    @abstractmethod
    def path(self):
        pass

    @abstractmethod
    def get_key(self, entry: "DataIndexEntry") -> "DataIndexKey":
        pass

    @abstractmethod
    def get(self, entry: "DataIndexEntry") -> tuple["FileSystem", str]:
        pass

    def exists(self, entry: "DataIndexEntry") -> bool:
        fs, path = self.get(entry)
        return fs.exists(path)

    def bulk_exists(
        self,
        entries: list["DataIndexEntry"],
        refresh: bool = False,
        jobs: Optional[int] = None,
        callback: "Callback" = DEFAULT_CALLBACK,
    ) -> dict["DataIndexEntry", bool]:
        results = {}
        for entry in callback.wrap(entries):
            results[entry] = self.exists(entry)

        return results


class ObjectStorage(Storage):
    def __init__(
        self,
        key: "DataIndexKey",
        odb: "HashFileDB",
        index: Optional["DataIndex"] = None,
        read_only: bool = False,
    ):
        self.odb = odb
        self.index = index
        super().__init__(key, read_only=read_only)

    def __repr__(self) -> str:
        params = ", ".join(f"{k}={v!r}" for k, v, *_ in self.__rich_repr__())
        return f"{self.__class__.__name__}({params})"

    def __rich_repr__(self):
        yield "key", self.key
        yield "odb", self.odb
        yield "index", self.index, None
        yield "read_only", self.read_only, False

    @property
    def fs(self):
        return self.odb.fs

    @property
    def path(self):
        return self.odb.path

    def get_key(self, entry: "DataIndexEntry") -> "DataIndexKey":
        if not entry.hash_info or not entry.hash_info.value:
            raise ValueError

        return self.odb._oid_parts(entry.hash_info.value)

    def get(self, entry: "DataIndexEntry") -> tuple["FileSystem", str]:
        if not entry.hash_info:
            raise ValueError

        return self.odb.fs, self.odb.oid_to_path(entry.hash_info.value)

    def exists(self, entry: "DataIndexEntry", refresh: bool = False) -> bool:
        if not entry.hash_info:
            return False

        value = cast("str", entry.hash_info.value)

        if self.index is None:
            return self.odb.exists(value)

        key = self.odb._oid_parts(value)
        if not refresh:
            return key in self.index

        try:
            from .build import build_entry

            fs, path = self.get(entry)
            self.index[key] = build_entry(path, fs)
            return True
        except FileNotFoundError:
            self.index.pop(key, None)
            return False
        finally:
            self.index.commit()

    def bulk_exists(
        self,
        entries: list["DataIndexEntry"],
        refresh: bool = False,
        jobs: Optional[int] = None,
        callback: "Callback" = DEFAULT_CALLBACK,
    ) -> dict["DataIndexEntry", bool]:
        entries_with_hash = [e for e in entries if e.hash_info]
        entries_without_hash = [e for e in entries if not e.hash_info]
        results = dict.fromkeys(entries_without_hash, False)
        callback.relative_update(len(entries_without_hash))

        if not entries_with_hash:
            return results

        if self.index is None or not refresh:
            for entry in callback.wrap(entries_with_hash):
                assert entry.hash_info
                value = cast("str", entry.hash_info.value)
                if self.index is None:
                    exists = self.odb.exists(value)
                else:
                    key = self.odb._oid_parts(value)
                    exists = key in self.index
                results[entry] = exists
            return results

        entry_map: dict[str, DataIndexEntry] = {
            self.get(entry)[1]: entry for entry in entries_with_hash
        }

        try:
            self.fs.ls(self.odb.path)  # check for fs access
        except FileNotFoundError:
            pass

        info_results = self.fs.info(
            list(entry_map.keys()),
            batch_size=jobs,
            return_exceptions=True,
            callback=callback,
        )

        for (path, entry), info in zip(entry_map.items(), info_results):
            assert entry.hash_info  # built from entries_with_hash
            value = cast("str", entry.hash_info.value)
            key = self.odb._oid_parts(value)

            if isinstance(info, FileNotFoundError) or info is None:
                self.index.pop(key, None)
                results[entry] = False
                continue
            if isinstance(info, Exception):
                raise info

            from .build import build_entry

            built_entry = build_entry(path, self.fs, info=info)
            self.index[key] = built_entry
            results[entry] = True

        if self.index is not None:
            self.index.commit()

        return results


class FileStorage(Storage):
    def __init__(
        self,
        key: "DataIndexKey",
        fs: "FileSystem",
        path: "str",
        index: Optional["DataIndex"] = None,
        prefix: Optional["DataIndexKey"] = None,
        read_only: bool = False,
    ):
        self._fs = fs
        self._path = path
        self.index = index
        self.prefix = prefix if prefix is not None else key
        super().__init__(key, read_only=read_only)

    def __repr__(self) -> str:
        params = ", ".join(f"{k}={v!r}" for k, v, *_ in self.__rich_repr__())
        return f"{self.__class__.__name__}({params})"

    def __rich_repr__(self):
        yield "key", self.key
        yield "fs", self.fs
        yield "index", self.index, None
        yield "prefix", self.prefix, None
        yield "read_only", self.read_only, False

    @property
    def fs(self):
        return self._fs

    @property
    def path(self):
        return self._path

    def get_key(self, entry: "DataIndexEntry") -> "DataIndexKey":
        assert entry.key
        assert entry.key[: len(self.prefix)] == self.prefix
        return entry.key[len(self.prefix) :]

    def get(self, entry: "DataIndexEntry") -> tuple["FileSystem", str]:
        assert entry.key is not None
        assert entry.key[: len(self.prefix)] == self.prefix
        path = self.fs.join(self.path, *entry.key[len(self.prefix) :])

        if not self.fs.version_aware:
            return self.fs, path

        if not entry.meta or entry.meta.isdir:
            return self.fs, path

        if entry.meta and entry.meta.version_id:
            return self.fs, self.fs.version_path(path, entry.meta.version_id)

        raise ValueError(f"Missing version_id for {path}")

    def exists(self, entry: "DataIndexEntry", refresh: bool = False) -> bool:
        if self.index is None:
            return super().exists(entry)

        assert entry.key
        assert entry.key[: len(self.prefix)] == self.prefix
        key = entry.key[len(self.prefix) :]
        if not refresh:
            return key in self.index

        try:
            from .build import build_entry

            fs, path = self.get(entry)
            self.index[key] = build_entry(path, fs)
            return True
        except FileNotFoundError:
            self.index.pop(key, None)
            return False
        finally:
            self.index.commit()


@attrs.define
class StorageInfo:
    """Describes where the data contents could be found"""

    # could be in memory
    data: Optional[Storage] = None
    # typically localfs
    cache: Optional[Storage] = None
    # typically cloud
    remote: Optional[Storage] = None


class StorageError(Exception):
    pass


class StorageKeyError(StorageError, KeyError):
    pass


class StorageMapping(MutableMapping):
    def __init__(self, *args, **kwargs):
        self._map = dict(*args, **kwargs)

    def __repr__(self):
        return f"{self.__class__.__name__}({self._map!r})"

    def __rich_repr__(self):
        yield self._map

    def __setitem__(self, key, value):
        self._map[key] = value

    def __delitem__(self, key):
        del self._map[key]

    def __getitem__(self, key):
        storages = []
        for prefix, storage in self._map.items():
            if len(prefix) > len(key):
                continue

            if key[: len(prefix)] == prefix:
                storages.append((prefix, storage))

        if not storages:
            raise StorageKeyError(key)

        storages = sorted(storages, key=lambda entry: len(entry[0]), reverse=True)
        data = None
        cache = None
        remote = None
        for _, storage in storages:
            if data is None:
                data = storage.data
            if cache is None:
                cache = storage.cache
            if remote is None:
                remote = storage.remote
            if data and cache and remote:
                break

        return StorageInfo(data=data, cache=cache, remote=remote)

    def __iter__(self):
        yield from self._map.keys()

    def __len__(self):
        return len(self._map)

    def add_data(self, storage: "Storage"):
        info = self.get(storage.key) or StorageInfo()
        info.data = storage
        self[storage.key] = info

    def add_cache(self, storage: "Storage"):
        info = self.get(storage.key) or StorageInfo()
        info.cache = storage
        self[storage.key] = info

    def add_remote(self, storage: "Storage"):
        info = self.get(storage.key) or StorageInfo()
        info.remote = storage
        self[storage.key] = info

    def get_storage_odb(self, entry: "DataIndexEntry", typ: str) -> "HashFileDB":
        info = self[entry.key]
        storage = getattr(info, typ)
        if not storage:
            raise StorageKeyError(entry.key)

        if not isinstance(storage, ObjectStorage):
            raise StorageKeyError(entry.key)

        return storage.odb

    def get_data_odb(self, entry: "DataIndexEntry") -> "HashFileDB":
        return self.get_storage_odb(entry, "data")

    def get_cache_odb(self, entry: "DataIndexEntry") -> "HashFileDB":
        return self.get_storage_odb(entry, "cache")

    def get_remote_odb(self, entry: "DataIndexEntry") -> "HashFileDB":
        return self.get_storage_odb(entry, "remote")

    def get_storage(
        self, entry: "DataIndexEntry", typ: str
    ) -> tuple["FileSystem", str]:
        info = self[entry.key]
        storage = getattr(info, typ)
        if not storage:
            raise StorageKeyError(entry.key)

        return storage.get(entry)

    def get_data(self, entry: "DataIndexEntry") -> tuple["FileSystem", str]:
        return self.get_storage(entry, "data")

    def get_cache(self, entry: "DataIndexEntry") -> tuple["FileSystem", str]:
        return self.get_storage(entry, "cache")

    def get_remote(self, entry: "DataIndexEntry") -> tuple["FileSystem", str]:
        return self.get_storage(entry, "remote")

    def cache_exists(self, entry: "DataIndexEntry", **kwargs) -> bool:
        storage = self[entry.key]
        if not storage.cache:
            raise StorageKeyError(entry.key)

        return storage.cache.exists(entry, **kwargs)

    def remote_exists(self, entry: "DataIndexEntry", **kwargs) -> bool:
        storage = self[entry.key]
        if not storage.remote:
            raise StorageKeyError(entry.key)

        return storage.remote.exists(entry, **kwargs)

    def _bulk_storage_exists(
        self,
        entries: list[DataIndexEntry],
        storage: str,
        **kwargs,
    ) -> dict[DataIndexEntry, bool]:
        by_storage: dict[Storage, list[DataIndexEntry]] = defaultdict(list)
        by_odb: dict[Optional[HashFileDB], dict[Storage, list[DataIndexEntry]]] = (
            defaultdict(lambda: defaultdict(list))
        )
        for entry in entries:
            storage_info = self[entry.key]
            storage_obj = getattr(storage_info, storage) if storage_info else None
            if isinstance(storage_obj, ObjectStorage):
                by_odb[storage_obj.odb][storage_obj].append(entry)
            elif storage_obj is not None:
                by_storage[storage_obj].append(entry)

        for storages in by_odb.values():
            assert storages  # cannot be empty, we always add at least one entry
            representative = next(iter(storages))
            by_storage[representative] = [
                e for entries in storages.values() for e in entries
            ]

        results = {}

        for storage_obj, storage_entries in by_storage.items():
            results.update(
                storage_obj.bulk_exists(
                    storage_entries,
                    **kwargs,
                )
            )

        return results

    def bulk_cache_exists(
        self,
        entries: list[DataIndexEntry],
        callback: Callback = DEFAULT_CALLBACK,
        **kwargs,
    ) -> dict[DataIndexEntry, bool]:
        return self._bulk_storage_exists(
            entries,
            "cache",
            callback=callback,
            **kwargs,
        )

    def bulk_remote_exists(
        self,
        entries: list[DataIndexEntry],
        callback: Callback = DEFAULT_CALLBACK,
        **kwargs,
    ) -> dict[DataIndexEntry, bool]:
        return self._bulk_storage_exists(
            entries,
            "remote",
            callback=callback,
            **kwargs,
        )


class BaseDataIndex(ABC, MutableMapping[DataIndexKey, DataIndexEntry]):
    storage_map: StorageMapping

    @abstractmethod
    def iteritems(
        self,
        prefix: Optional[DataIndexKey] = None,
        shallow: bool = False,
    ) -> Iterator[tuple[DataIndexKey, DataIndexEntry]]:
        pass

    @abstractmethod
    def traverse(self, node_factory: Callable, **kwargs) -> Any:
        pass

    @abstractmethod
    def has_node(self, key: DataIndexKey) -> bool:
        pass

    @abstractmethod
    def delete_node(self, key: DataIndexKey) -> None:
        pass

    @abstractmethod
    def longest_prefix(
        self, key: DataIndexKey
    ) -> tuple[Optional[DataIndexKey], Optional[DataIndexEntry]]:
        pass

    def _get_meta(self, key, entry):
        if entry.hash_info:
            return Meta()

        info = self.storage_map.get(key)
        if not info:
            return None

        for storage in [info.data, info.cache, info.remote]:
            if not storage:
                continue

            if not isinstance(storage, FileStorage):
                continue

            fs, path = storage.get(entry)
            try:
                info = fs.info(path)
                return Meta(isdir=(info["type"] == "directory"))
            except FileNotFoundError:
                continue

        return None

    def _info_from_entry(self, key, entry):
        if entry is None:
            return {
                "type": "directory",
                "size": 0,
                "isexec": False,
                "entry": None,
            }

        meta = entry.meta
        if meta is None:
            meta = self._get_meta(key, entry)
            entry.meta = meta

        isdir = meta and meta.isdir
        ret = {
            "type": "directory" if isdir else "file",
            "size": meta.size if meta else 0,
            "isexec": meta.isexec if meta else False,
            "entry": entry,
        }

        if entry.hash_info:
            assert entry.hash_info.name
            ret[entry.hash_info.name] = entry.hash_info.value

        return ret

    def add(self, entry: DataIndexEntry):
        self[cast("DataIndexKey", entry.key)] = entry

    @abstractmethod
    def ls(self, root_key: DataIndexKey, detail=True):
        pass

    def info(self, key: DataIndexKey):
        try:
            entry = self[key]
        except ShortKeyError:
            entry = None

        return self._info_from_entry(key, entry)


def _load_from_object_storage(trie, root_entry, storage):
    if not root_entry.hash_info or not root_entry.hash_info.isdir:
        raise FileNotFoundError

    obj = Tree.load(storage.odb, root_entry.hash_info, hash_name=storage.odb.hash_name)

    dirs = set()
    for ikey, (meta, hash_info) in obj.iteritems():
        if not meta and root_entry.hash_info and root_entry.hash_info == hash_info:
            meta = root_entry.meta

        if len(ikey) >= 2:
            # NOTE: current .dir obj format doesn't include subdirs, so
            # we need to create entries for them manually.
            for idx in range(1, len(ikey)):
                dirs.add(ikey[:-idx])

        entry_key = root_entry.key + ikey
        child_entry = DataIndexEntry(
            key=entry_key,
            hash_info=hash_info,
            meta=meta,
        )
        trie[entry_key] = child_entry

    for dkey in dirs:
        entry_key = root_entry.key + dkey
        trie[entry_key] = DataIndexEntry(
            key=entry_key,
            meta=Meta(isdir=True),
            loaded=True,
        )


def _load_from_file_storage(trie, root_entry, storage):
    from .build import build_entries

    fs, path = storage.get(root_entry)

    if not fs.exists(path):
        raise FileNotFoundError(errno.ENOENT, os.strerror(errno.ENOENT), path)

    for entry in build_entries(path, fs):
        entry.key = root_entry.key + entry.key
        trie[entry.key] = entry


class DataIndexError(Exception):
    pass


class DataIndexDirError(DataIndexError):
    pass


def _load_from_storage(trie, entry, storage_info):
    last_exc = None

    for storage in [
        storage_info.data,
        storage_info.cache,
        storage_info.remote,
    ]:
        if not storage:
            continue

        try:
            if isinstance(storage, ObjectStorage):
                _load_from_object_storage(trie, entry, storage)
            else:
                _load_from_file_storage(trie, entry, storage)
            return True
        except Exception as exc:  # noqa: BLE001
            # NOTE: this might be some random fs exception, e.g. auth error
            last_exc = exc
            logger.debug(
                "failed to load %s from storage %s (%s)",
                entry.key,
                storage.fs.protocol,
                storage.path,
                exc_info=True,
            )

    raise DataIndexDirError(f"failed to load directory {entry.key}") from last_exc


class DataIndex(BaseDataIndex, MutableMapping[DataIndexKey, DataIndexEntry]):
    def __init__(self, *args, **kwargs):
        # NOTE: by default, using an in-memory pygtrie trie that doesn't
        # serialize values, so we can save some time.
        self._trie = PyGTrie()

        self.storage_map = StorageMapping()

        def _onerror(_, exc):
            raise exc

        self.onerror = _onerror

        self.update(*args, **kwargs)

    @classmethod
    def open(cls, path):
        ret = cls()
        ret._trie = DataIndexTrie.open(path)
        return ret

    def view(self, key):
        import copy

        ret = DataIndex()
        ret._trie = self._trie.view(key)
        ret.storage_map = copy.deepcopy(self.storage_map)
        return ret

    def commit(self):
        self._trie.commit()

    def rollback(self):
        self._trie.rollback()

    def close(self):
        self._trie.close()

    def __setitem__(self, key, value):
        self._trie[key] = value

    def __getitem__(self, key):
        item = self._trie.get(key)
        if item:
            if item.meta is None:
                item.meta = self._get_meta(key, item)
            return item

        lprefix = self._trie.longest_prefix(key)
        if lprefix is not None:
            dir_key, dir_entry = lprefix
            self._load(dir_key, dir_entry)

        return self._trie[key]

    def __delitem__(self, key):
        del self._trie[key]

    def __iter__(self):
        return iter(self._trie)

    def __len__(self):
        return len(self._trie)

    def _load(self, key, entry):
        if not entry:
            return

        if entry.loaded:
            return

        if not entry.meta or not entry.meta.isdir:
            return

        storage_info = self.storage_map.get(key)
        if storage_info is None:
            return

        try:
            _load_from_storage(self._trie, entry, storage_info)
        except DataIndexDirError as exc:
            self.onerror(entry, exc)
            return

        entry.loaded = True
        del self._trie[key]
        self._trie[key] = entry
        self._trie.commit()

    def load(self, **kwargs):
        kwargs["shallow"] = True
        for _ in self.iteritems(**kwargs):
            pass

    def has_node(self, key: DataIndexKey) -> bool:
        return self._trie.has_node(key)

    def delete_node(self, key: DataIndexKey) -> None:
        return self._trie.delete_node(key)

    def shortest_prefix(self, *args, **kwargs):
        return self._trie.shortest_prefix(*args, **kwargs)

    def longest_prefix(
        self, key: DataIndexKey
    ) -> tuple[Optional[DataIndexKey], Optional[DataIndexEntry]]:
        return self._trie.longest_prefix(key)

    def traverse(self, *args, **kwargs) -> Any:
        return self._trie.traverse(*args, **kwargs)

    def iteritems(
        self,
        prefix: Optional[DataIndexKey] = None,
        shallow: bool = False,
    ) -> Iterator[tuple[DataIndexKey, DataIndexEntry]]:
        if prefix:
            item = self._trie.longest_prefix(prefix)
            if item:
                key, entry = item
                self._load(key, entry)

        for key, entry in self._trie.items(prefix=prefix, shallow=shallow):
            self._load(key, entry)
            yield key, entry

    def iterkeys(self, *args, **kwargs):
        return self._trie.keys(*args, **kwargs)

    def _ensure_loaded(self, prefix):
        entry = self.get(prefix)
        if entry and entry.meta and entry.meta.isdir and not entry.loaded:
            self._load(prefix, entry)

    def ls(self, root_key: DataIndexKey, detail=True):
        self._ensure_loaded(root_key)
        if detail:
            yield from (
                (key, self._info_from_entry(key, entry))
                for key, entry in self._trie.ls(root_key, with_values=True)
            )
        else:
            yield from self._trie.ls(root_key)
