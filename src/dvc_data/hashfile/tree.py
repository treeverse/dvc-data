import json
import logging
import posixpath
from collections.abc import Iterable
from typing import TYPE_CHECKING, Any, Final, Optional

from dvc_objects.errors import ObjectFormatError

from dvc_data.compat import cached_property
from dvc_data.hashfile.hash import DEFAULT_ALGORITHM, hash_file
from dvc_data.hashfile.meta import Meta
from dvc_data.hashfile.obj import HashFile

if TYPE_CHECKING:
    from pygtrie import Trie

    from dvc_data.hashfile.db import HashFileDB
    from dvc_data.hashfile.hash_info import HashInfo

logger = logging.getLogger(__name__)


class TreeError(Exception):
    pass


class MergeError(Exception):
    pass


def _try_load(
    odbs: Iterable["HashFileDB"],
    hash_info: "HashInfo",
) -> Optional["HashFile"]:
    for odb in odbs:
        if not odb:
            continue

        try:
            return Tree.load(odb, hash_info)
        except (FileNotFoundError, ObjectFormatError):
            pass

    return None


class Tree(HashFile):
    PARAM_RELPATH: Final = "relpath"

    def __init__(self):
        # this should really be part of a TreeBuilder.
        # HashFile does not support these properties as none values, so we may be losing
        # type-safety with this.
        self.fs = None  # type: ignore[assignment]
        self.path = None  # type: ignore[assignment]
        self.hash_info = None  # type: ignore[assignment]
        self.oid = None  # type: ignore[assignment]
        self._dict: dict[
            tuple[str, ...], tuple[Optional[Meta], Optional[HashInfo]]
        ] = {}

    @cached_property
    def _trie(self) -> "Trie":
        from pygtrie import Trie

        return Trie(self._dict)

    def add(
        self,
        key: tuple[str, ...],
        meta: Optional["Meta"],
        oid: Optional["HashInfo"],
    ):
        self.__dict__.pop("_trie", None)
        self._dict[key] = (meta, oid)

    def get(
        self, key: tuple[str, ...], default=None
    ) -> Optional[tuple[Optional["Meta"], Optional["HashInfo"]]]:
        return self._dict.get(key, default)

    def digest(self, with_meta: bool = False, name: str = DEFAULT_ALGORITHM):
        from dvc_objects.fs import MemoryFileSystem
        from dvc_objects.fs.utils import tmp_fname

        memfs = MemoryFileSystem()
        path = "memory://{}".format(tmp_fname(""))
        memfs.pipe_file(path, self.as_bytes())
        _, self.hash_info = hash_file(path, memfs, name)
        assert self.hash_info.value
        self.fs = memfs
        if with_meta:
            self.path = path + ".with_meta"
            memfs.pipe_file(self.path, self.as_bytes(with_meta=True))
        else:
            self.path = path
        self.hash_info.value += ".dir"
        self.oid = self.hash_info.value

    def _load(self, key, meta, hash_info):
        if hash_info and hash_info.isdir and not meta.obj:
            meta.obj = _try_load([meta.odb, meta.remote], hash_info)
            if meta.obj:
                for ikey, value in meta.obj.iteritems():
                    self._trie[key + ikey] = value
                    self._dict[key + ikey] = value

    def iteritems(self, prefix=None):
        kwargs = {}
        if prefix:
            kwargs = {"prefix": prefix}
            item = self._trie.longest_prefix(prefix)
            if item:
                key, (meta, hash_info) = item
                self._load(key, meta, hash_info)

        for key, (meta, hash_info) in self._trie.iteritems(**kwargs):
            self._load(key, meta, hash_info)
            yield key, (meta, hash_info)

    def shortest_prefix(self, *args, **kwargs):
        return self._trie.shortest_prefix(*args, **kwargs)

    def __len__(self):
        return len(self._dict)

    def __iter__(self):
        yield from ((key, value[0], value[1]) for key, value in self._dict.items())

    def as_dict(self):
        return self._dict.copy()

    def as_list(self, with_meta: bool = False):
        from operator import itemgetter

        def _hi_to_dict(hi: Optional["HashInfo"]) -> dict[str, Any]:
            if not hi:
                return {}
            if hi.name == "md5-dos2unix":
                return {"md5": hi.value}
            return hi.to_dict()

        # Sorting the list by path to ensure reproducibility
        return sorted(
            (
                {
                    **(meta.to_dict() if with_meta else {}),
                    **_hi_to_dict(hi),
                    self.PARAM_RELPATH: posixpath.sep.join(parts),
                }
                for parts, meta, hi in self
            ),
            key=itemgetter(self.PARAM_RELPATH),
        )

    def as_trie(self) -> "Trie":
        return self._trie.copy()

    def as_bytes(self, with_meta: bool = False):
        return json.dumps(self.as_list(with_meta=with_meta), sort_keys=True).encode(
            "utf-8"
        )

    @classmethod
    def from_list(cls, lst, hash_name: Optional[str] = None):
        from dvc_data.hashfile.hash_info import HashInfo

        tree = cls()
        for _entry in lst:
            entry = _entry.copy()
            relpath = entry.pop(cls.PARAM_RELPATH)
            parts = tuple(relpath.split(posixpath.sep))
            meta = Meta.from_dict(entry)
            if hash_name:
                meta_name = "md5" if hash_name == "md5-dos2unix" else hash_name
                hash_info = HashInfo(hash_name, getattr(meta, meta_name))
            else:
                hash_info = HashInfo.from_dict(entry)
            tree.add(parts, meta, hash_info)
        return tree

    @classmethod
    def from_trie(cls, trie: "Trie") -> "Tree":
        tree = cls()
        tree._dict = dict(trie.iteritems())
        return tree

    @classmethod
    def load(cls, odb, hash_info, hash_name: Optional[str] = None) -> "Tree":
        obj = odb.get(hash_info.value)

        try:
            with obj.fs.open(obj.path, "r") as fobj:
                raw = json.load(fobj)
        except ValueError as exc:
            raise ObjectFormatError(f"{obj} is corrupted") from exc

        if not isinstance(raw, list):
            logger.debug(
                "dir cache file format error '%s' [skipping the file]",
                obj.path,
            )
            raise ObjectFormatError(f"{obj} is corrupted")

        if hash_name is None and odb.hash_name == "md5-dos2unix":
            hash_name = "md5-dos2unix"
        try:
            tree = cls.from_list(raw, hash_name=hash_name)
        except (AttributeError, KeyError, TypeError, ValueError) as exc:
            raise ObjectFormatError(f"{obj} is corrupted") from exc
        tree.path = obj.path
        tree.fs = obj.fs
        tree.hash_info = hash_info
        tree.oid = hash_info.value

        return tree

    def filter(self, prefix: tuple[str]) -> Optional["Tree"]:
        """Return a filtered copy of this tree that only contains entries
        inside prefix.

        The returned tree will contain the original tree's hash_info and
        path.

        Returns an empty tree if no object exists at the specified prefix.
        """
        tree = Tree()
        tree.path = self.path
        tree.fs = self.fs
        tree.hash_info = self.hash_info
        tree.oid = self.oid
        try:
            for key, (meta, oid) in self._trie.items(prefix):
                tree.add(key, meta, oid)
        except KeyError:
            pass
        return tree

    def get_obj(self, odb, prefix: tuple[str]) -> Optional[HashFile]:
        """Return object at the specified prefix in this tree.

        Returns None if no object exists at the specified prefix.
        """
        _, hi = self._dict.get(prefix) or (None, None)
        if hi:
            return odb.get(hi.value)

        tree = Tree()
        depth = len(prefix)
        try:
            for key, (meta, entry_oid) in self._trie.items(prefix):
                tree.add(key[depth:], meta, entry_oid)
        except KeyError:
            return None
        tree.digest()
        return tree

    def ls(self, prefix=None):
        kwargs = {}
        if prefix:
            kwargs["prefix"] = prefix

        meta, hash_info = self._trie.get(prefix, (None, None))
        if hash_info and hash_info.isdir and meta and not meta.obj:
            raise TreeError

        ret = []

        def node_factory(_, key, children, *args):
            if key == prefix:
                list(children)
            else:
                ret.append(key[-1])

        self._trie.traverse(node_factory, **kwargs)

        return ret


def du(odb, tree):
    try:
        return sum(odb.fs.size(odb.oid_to_path(oid.value)) for _, _, oid in tree)
    except FileNotFoundError:
        return None


def _diff(ancestor, other, allowed=None):
    from dictdiffer import diff

    if not allowed:
        allowed = ["add"]

    result = list(diff(ancestor, other))
    for typ, _, _ in result:
        if typ not in allowed:
            raise MergeError(
                "unable to auto-merge directories with diff that contains "
                f"'{typ}'ed files"
            )
    return result


def _merge(ancestor, our, their, allowed=None):
    import copy

    from dictdiffer import diff, patch

    our_diff = _diff(ancestor, our, allowed=allowed)
    if not our_diff:
        return copy.deepcopy(their)

    their_diff = _diff(ancestor, their, allowed=allowed)
    if not their_diff:
        return copy.deepcopy(our)

    # make sure there are no conflicting files
    try:
        patch_ours_first = patch(our_diff + their_diff, ancestor)
        patch_theirs_first = patch(their_diff + our_diff, ancestor)
    except KeyError as e:
        # todo: fails if both diffs delete the same object
        raise MergeError(  # noqa: B904
            f"unable to auto-merge the following paths:\nboth deleted: {e}"
        )
    unmergeable = list(diff(patch_ours_first, patch_theirs_first))
    if unmergeable:
        unmergeable_paths = []
        for paths in patch(unmergeable, {}):
            unmergeable_paths.append(posixpath.join(*paths))
        raise MergeError(
            "unable to auto-merge the following paths:\n" + "\n".join(unmergeable_paths)
        )
    return patch_ours_first


def merge(odb, ancestor_info, our_info, their_info, allowed=None):
    from . import load

    assert our_info
    assert their_info

    if ancestor_info:
        ancestor = load(odb, ancestor_info)
        assert isinstance(ancestor, Tree)
    else:
        ancestor = Tree()

    our = load(odb, our_info)
    assert isinstance(our, Tree)

    their = load(odb, their_info)
    assert isinstance(their, Tree)

    merged_dict = _merge(
        ancestor.as_dict(), our.as_dict(), their.as_dict(), allowed=allowed
    )

    merged = Tree()
    for key, (meta, oid) in merged_dict.items():
        merged.add(key, meta, oid)
    merged.digest()

    return merged


def update_meta(ours: "Tree", theirs: "Tree") -> "Tree":
    """Return a new copy of `ours` using meta updated from `theirs`.

    Entries that exist in both trees (with matching key + hashinfo) will be
    updated to use the meta from `theirs`.
    """
    updated = Tree()
    for key, meta, hash_info in ours:
        theirs_meta, theirs_hash_info = theirs.get(  # type: ignore[misc]
            key, (None, None)
        )
        if hash_info is not None and hash_info == theirs_hash_info:
            meta = theirs_meta
        updated.add(key, meta, hash_info)
    # We do not need to do a full digest() here since we are not modifying any
    # keys or hashinfos from the original `ours`.
    updated.fs = ours.fs
    updated.path = ours.path
    updated.hash_info = ours.hash_info
    updated.oid = ours.oid
    return updated
