"""Manages state database used for checksum caching."""

import logging
import os
from abc import ABC, abstractmethod
from collections.abc import Iterable, Iterator
from itertools import zip_longest
from typing import TYPE_CHECKING, Optional, Union

from dvc_objects.fs import LocalFileSystem
from dvc_objects.fs.system import inode as get_inode
from dvc_objects.fs.utils import relpath
from fsspec.utils import tokenize

from dvc_data.json_compat import dumps as json_dumps
from dvc_data.json_compat import loads as json_loads

from .hash_info import HashInfo
from .meta import Meta
from .utils import get_mtime_and_size

if TYPE_CHECKING:
    from dvc_objects.fs import FileSystem

    from ._ignore import Ignore


logger = logging.getLogger(__name__)


class StateBase(ABC):
    @abstractmethod
    def close(self):
        pass

    @abstractmethod
    def save(
        self,
        path: str,
        fs: "FileSystem",
        hash_info: "HashInfo",
        info: Optional[dict] = None,
    ) -> None:
        pass

    @abstractmethod
    def save_many(
        self, items: Iterable[tuple[str, "HashInfo", Optional[dict]]], fs: "FileSystem"
    ) -> None:
        pass

    @abstractmethod
    def get(
        self, path: str, fs: "FileSystem", info: Optional[dict] = None
    ) -> Union[tuple[None, None], tuple["Meta", HashInfo]]:
        pass

    @abstractmethod
    def get_many(
        self, items: Iterable[str], fs: "FileSystem", infos: dict[str, dict]
    ) -> Iterator[Union[tuple[str, None, None], tuple[str, "Meta", "HashInfo"]]]:
        pass

    @abstractmethod
    def set_link(self, path, inode, mtime):
        pass

    @abstractmethod
    def save_link(self, path, fs):
        pass

    @abstractmethod
    def get_unused_links(self, used, fs):
        pass

    @abstractmethod
    def remove_links(self, unused, fs):
        pass


class StateNoop(StateBase):
    def close(self):
        pass

    def save(
        self,
        path: str,
        fs: "FileSystem",
        hash_info: "HashInfo",
        info: Optional[dict] = None,
    ) -> None:
        pass

    def save_many(
        self, items: Iterable[tuple[str, "HashInfo", Optional[dict]]], fs: "FileSystem"
    ) -> None:
        pass

    def get(
        self, path: str, fs: "FileSystem", info: Optional[dict] = None
    ) -> Union[tuple[None, None], tuple["Meta", HashInfo]]:
        return (None, None)

    def get_many(
        self, items: Iterable[str], fs: "FileSystem", infos: dict[str, dict]
    ) -> Iterator[Union[tuple[str, None, None], tuple[str, "Meta", "HashInfo"]]]:
        yield from zip_longest(items, [], [])

    def set_link(self, path, inode, mtime):
        pass

    def save_link(self, path, fs):
        pass

    def get_unused_links(self, used, fs):
        return []

    def remove_links(self, unused, fs):
        pass


def _checksum(info):
    return str(int(tokenize([info["ino"], info["mtime"], info["size"]]), 16))


class State(StateBase):
    HASH_VERSION = 1

    def __init__(self, root_dir=None, tmp_dir=None, ignore: Optional["Ignore"] = None):
        from .cache import Cache, HashesCache

        super().__init__()

        self.tmp_dir = tmp_dir
        self.root_dir = root_dir
        self.ignore = ignore

        if not tmp_dir:
            return

        links_dir = os.path.join(tmp_dir, "links")
        hashes_dir = os.path.join(tmp_dir, "hashes", "local")
        self.links = Cache(links_dir)
        self.hashes = HashesCache(hashes_dir)

    def close(self):
        self.hashes.close()
        self.links.close()

    def save(
        self,
        path: str,
        fs: "FileSystem",
        hash_info: "HashInfo",
        info: Optional[dict] = None,
    ) -> None:
        """Save hash for the specified path info.

        Args:
            path (str): path to save hash for.
            hash_info (HashInfo): hash to save.
        """

        if not isinstance(fs, LocalFileSystem):
            return

        info = info or fs.info(path)
        entry = {
            "version": self.HASH_VERSION,
            "checksum": _checksum(info),
            "size": info["size"],
            "hash_info": hash_info.to_dict(),
        }

        self.hashes[path] = json_dumps(entry)

    def save_many(
        self, items: Iterable[tuple[str, "HashInfo", Optional[dict]]], fs: "FileSystem"
    ) -> None:
        if not isinstance(fs, LocalFileSystem):
            return

        lst: list[tuple[str, str]] = []
        for path, hash_info, info in items:
            try:
                info = info or fs.info(path)
            except FileNotFoundError:
                continue

            entry = {
                "version": self.HASH_VERSION,
                "checksum": _checksum(info),
                "size": info["size"],
                "hash_info": hash_info.to_dict(),
            }
            lst.append((path, json_dumps(entry)))
        return self.hashes.set_many(lst)

    def get(
        self, path: str, fs: "FileSystem", info: Optional[dict] = None
    ) -> Union[tuple[None, None], tuple["Meta", HashInfo]]:
        """Gets the hash for the specified path info. Hash will be
        retrieved from the state database if available.

        Args:
            path (str): path info to get the hash for.

        Returns:
            HashInfo or None: hash for the specified path info or None if it
            doesn't exist in the state database.
        """

        if not isinstance(fs, LocalFileSystem):
            return None, None

        raw = self.hashes.get(path)
        if not raw:
            return None, None

        try:
            info = info or fs.info(path)
        except FileNotFoundError:
            return None, None

        if r := self._get(path, raw, info):
            return r
        return None, None

    def _get(
        self, path: str, raw: str, info: dict
    ) -> Optional[tuple["Meta", HashInfo]]:
        try:
            entry = json_loads(raw)
        except ValueError:
            return None

        actual = _checksum(info)
        if entry["checksum"] != actual:
            return None

        version: Optional[int] = entry.get("version")
        if version is not None and version > self.HASH_VERSION:
            return None

        meta = Meta.from_info(info)
        meta.size = meta.size if meta.size is not None else entry["size"]
        hash_info = HashInfo.from_dict(entry["hash_info"])
        if version is None and hash_info.name == "md5":
            hash_info.name = "md5-dos2unix"
        return meta, hash_info

    def get_many(
        self, items: Iterable[str], fs: "FileSystem", infos: dict[str, dict]
    ) -> Iterator[Union[tuple[str, None, None], tuple[str, "Meta", "HashInfo"]]]:
        if not isinstance(fs, LocalFileSystem):
            yield from zip_longest(items, [], [])
            return

        for path, raw in self.hashes.get_many(items):
            if not raw:
                yield path, None, None
                continue

            try:
                info = infos.get(path) or fs.info(path)
            except FileNotFoundError:
                yield path, None, None
                continue

            if r := self._get(path, raw, info):
                yield path, r[0], r[1]
            else:
                yield path, None, None

    def save_link(self, path, fs):
        """Adds the specified path to the list of links created by dvc. This
        list is later used on `dvc checkout` to cleanup old links.

        Args:
            path (str): path info to add to the list of links.
        """
        if not isinstance(fs, LocalFileSystem):
            return

        try:
            mtime, _ = get_mtime_and_size(path, fs, self.ignore)
        except FileNotFoundError:
            return

        inode = get_inode(path)
        return self.set_link(path, inode, mtime)

    def set_link(self, path, inode, mtime):
        relative_path = relpath(path, self.root_dir)
        with self.links as ref:
            ref[relative_path] = (inode, mtime)

    def get_unused_links(self, used, fs):
        """Removes all saved links except the ones that are used.

        Args:
            used (list): list of used links that should not be removed.
        """
        if not isinstance(fs, LocalFileSystem):
            return []

        unused = []

        with self.links as ref:
            # Materialize the keys: reading an entry written by an older,
            # pickle-serializing dvc-data drops it, which would mutate the
            # cache while we iterate it.
            for relative_path in list(ref):
                path = os.path.join(self.root_dir, relative_path)

                if path in used or not fs.exists(path):
                    continue

                entry = ref.get(relative_path)
                if entry is None:
                    continue

                inode = get_inode(path)
                mtime, _ = get_mtime_and_size(path, fs, self.ignore)

                # The link cache round-trips this pair through JSON, which has
                # no tuple type, so compare as a sequence rather than by type.
                if tuple(entry) == (inode, mtime):
                    logger.debug("Removing '%s' as unused link.", path)
                    unused.append(relative_path)

        return unused

    def remove_links(self, unused, fs):
        if not isinstance(fs, LocalFileSystem):
            return

        for path in unused:
            fs.remove(os.path.join(self.root_dir, path))

        with self.links as ref:
            for path in unused:
                del ref[path]
