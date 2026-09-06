import enum
import errno
import math
import os
import posixpath
import random
import stat
import sys
from collections import deque
from contextlib import closing
from itertools import accumulate
from pathlib import Path
from posixpath import relpath
from typing import Optional

import typer
from attrs import asdict
from dvc_objects.errors import ObjectFormatError
from dvc_objects.fs import LocalFileSystem, MemoryFileSystem
from tqdm import tqdm

from dvc_data.callbacks import TqdmCallback
from dvc_data.hashfile import load
from dvc_data.hashfile.build import build as _build
from dvc_data.hashfile.checkout import checkout as _checkout
from dvc_data.hashfile.db import HashFileDB
from dvc_data.hashfile.diff import ROOT
from dvc_data.hashfile.diff import diff as _diff
from dvc_data.hashfile.hash import algorithms_available
from dvc_data.hashfile.hash import file_md5 as _file_md5
from dvc_data.hashfile.hash import fobj_md5 as _fobj_md5
from dvc_data.hashfile.hash_info import HashInfo
from dvc_data.hashfile.obj import HashFile
from dvc_data.hashfile.state import State
from dvc_data.hashfile.transfer import transfer as _transfer
from dvc_data.hashfile.tree import Tree
from dvc_data.hashfile.tree import du as _du
from dvc_data.index.index import DataIndex
from dvc_data.repo import NotARepoError, Repo

file_type = typer.Argument(
    ...,
    exists=True,
    file_okay=True,
    dir_okay=False,
    readable=True,
    resolve_path=True,
    allow_dash=True,
    path_type=str,
)
dir_file_type = typer.Argument(
    ...,
    exists=True,
    file_okay=True,
    dir_okay=True,
    readable=True,
    resolve_path=True,
    allow_dash=True,
    path_type=str,
)

dir_file_type_no_dash_no_resolve = typer.Argument(
    ...,
    exists=True,
    file_okay=True,
    dir_okay=True,
    readable=True,
    path_type=str,
)

HashEnum = enum.Enum(  # type: ignore[misc]
    "HashEnum", {h: h for h in sorted(algorithms_available)}
)
LinkEnum = enum.Enum(  # type: ignore[misc]
    "LinkEnum", {lt: lt for lt in ["reflink", "hardlink", "symlink", "copy"]}
)
SIZE_HELP = "Human readable size, eg: '1kb', '100Mb', '10GB' etc"


# https://github.com/aws/aws-cli/blob/5aa599949f60b6af554fd5714d7161aa272716f7/awscli/customizations/s3/utils.py
MULTIPLIERS = {
    "kb": 1024,
    "mb": 1024**2,
    "gb": 1024**3,
    "tb": 1024**4,
    "kib": 1024,
    "mib": 1024**2,
    "gib": 1024**3,
    "tib": 1024**4,
}


def human_readable_to_bytes(value: str) -> int:
    value = value.lower()
    suffix = ""
    if value.endswith(tuple(MULTIPLIERS.keys())):
        size = 2
        size += value[-2] == "i"  # KiB, MiB etc
        value, suffix = value[:-size], value[-size:]

    multiplier = MULTIPLIERS.get(suffix, 1)
    return int(value) * multiplier


class Application(typer.Typer):
    def __init__(self, *args, **kwargs):
        kwargs.setdefault("no_args_is_help", True)
        super().__init__(*args, **kwargs)

    def command(self, *args, **kwargs):
        kwargs.setdefault("no_args_is_help", True)
        return super().command(*args, **kwargs)


app = Application(
    name="dvc-data",
    help="dvc-data testingtool",
    context_settings={"help_option_names": ["-h", "--help"]},
    add_completion=False,
)


def _version_callback(value: bool) -> None:
    import importlib.metadata

    if value:
        print(f"dvc-data, version {importlib.metadata.version('dvc-data')}")
        raise typer.Exit


@app.callback()
def _callback(
    version: bool = typer.Option(
        False,
        "--version",
        help="Show the version and exit.",
        callback=_version_callback,
        is_eager=True,
    ),
) -> None:
    pass


@app.command(name="hash", help="Compute checksum of the file")
def hash_file(
    file: Path = file_type,
    name: HashEnum = typer.Option("md5", "-n", "--name"),
):
    path = relpath(file)
    hash_name = name.value
    if path == "-":
        hash_value = _fobj_md5(sys.stdin.buffer, name=hash_name)
    else:
        hash_value = _file_md5(path, name=hash_name)
    print(hash_name, hash_value, sep=": ")


@app.command(help="Generate sparse file")
def gensparse(
    file: Path = typer.Argument(...),
    size: str = typer.Argument(..., help=SIZE_HELP),
):
    with file.open("wb") as f:
        f.seek(human_readable_to_bytes(size) - 1)
        f.write(b"\0")


@app.command(help="Generate file with random contents")
def genrand(
    file: Path = typer.Argument(...),
    size: str = typer.Argument(..., help=SIZE_HELP),
):
    with file.open("wb") as f:
        f.write(os.urandom(human_readable_to_bytes(size)))


def rand_gauss_int(num: int, sigma=0.2) -> int:
    return round(random.gauss(num, sigma * num))


def _gentree(root: Path, num_dirs, num_files, fsize, depth=1):
    for num in range(rand_gauss_int(num_files)):
        nzeros = int(math.log10(num_files)) + 1
        genrand(root / f"{num:0{nzeros}}.txt", size=str(rand_gauss_int(fsize)))

    if depth < 1:
        return

    for num in range(rand_gauss_int(num_dirs)):
        nzeros = int(math.log10(num_dirs)) + 1
        (dir_ := root / f"dir{num:0{nzeros}}").mkdir()
        _gentree(dir_, num_dirs, num_files, fsize, depth=depth - 1)


@app.command()
def gentree(
    path: Path,
    num: int,
    size: str = typer.Argument(0, help=SIZE_HELP),
    depth: int = 2,
    seed: int = 0,
):
    """Generate a random tree structure.

    Example:

    gentree dataset 10000

    gentree dataset 10000 1Gb

    gentree dataset 10000 --depth 5
    """
    assert depth >= 1
    files_per_dir = max(num // 1000, 1)
    total_dirs = num / files_per_dir
    dirs_per_dir = round(math.pow(total_dirs, 1 / depth))
    file_size = round(human_readable_to_bytes(size) / num)

    path.mkdir(parents=True)
    print(f"{total_dirs=}, {dirs_per_dir=}, {files_per_dir=}, {file_size=}, {depth=}")
    random.seed(seed)
    _gentree(path, dirs_per_dir, files_per_dir, file_size, depth=depth)


def from_shortoid(odb: HashFileDB, oid: str) -> str:
    oid = oid if oid != "-" else sys.stdin.read().strip()
    try:
        return odb.exists_prefix(oid)
    except KeyError as exc:
        typer.echo(f"Not a valid {oid=}", err=True)
        raise typer.Exit(1) from exc
    except ValueError as exc:
        typer.echo(f"Ambiguous {oid=}", err=True)
        raise typer.Exit(1) from exc


def get_odb(**config):
    try:
        repo = Repo.discover()
    except NotARepoError as exc:
        typer.echo(exc, err=True)
        raise typer.Abort(1)  # noqa: B904

    if "state" not in config:
        config.setdefault("state", State(root_dir=repo.root, tmp_dir=repo.tmp_dir))
    return HashFileDB(repo.fs, repo.object_dir, **config)


@app.command(help="Oid to path")
def o2p(oid: str = typer.Argument(..., allow_dash=True)):
    odb = get_odb()
    path = odb.oid_to_path(from_shortoid(odb, oid))
    print(path)


@app.command(help="Path to Oid")
def p2o(path: Path = typer.Argument(..., allow_dash=True)):
    odb = get_odb()
    fs_path = relpath(path)
    if fs_path == "-":
        fs_path = sys.stdin.read().strip()

    oid = odb.path_to_oid(fs_path)
    print(oid)


def _cat_object(odb, oid):
    path = odb.oid_to_path(oid)
    contents = odb.fs.cat_file(path)
    return typer.echo(contents)


@app.command(help="Provide content of the objects")
def cat(
    oid: str = typer.Argument(..., allow_dash=True),
    check: bool = typer.Option(False, "--check", "-c"),
):
    odb = get_odb()
    oid = from_shortoid(odb, oid)
    if check:
        try:
            return odb.check(oid, check_hash=True)
        except ObjectFormatError as exc:
            typer.echo(exc, err=True)
            raise typer.Exit(1) from exc
    return _cat_object(odb, oid)


@app.command(help="Build and optionally write object to the database")
def build(
    path: Path = dir_file_type,
    write: bool = typer.Option(False, "--write", "-w"),
    shallow: bool = False,
):
    odb = get_odb()
    fs_path = os.fspath(path)
    fs = odb.fs
    if fs_path == "-":
        fs = MemoryFileSystem()
        fs.put_file(sys.stdin.buffer, fs_path)

    with closing(odb.state):
        object_store, _, obj = _build(odb, fs_path, fs, name="md5")
        if write:
            _transfer(
                object_store,
                odb,
                {obj.hash_info},
                hardlink=True,
                shallow=shallow,
            )
    print(obj)
    return obj


def _ls_tree(tree):
    for key, _, hash_info in tree:
        print(hash_info.value, posixpath.sep.join(key), sep="\t")


@app.command("ls", help="List objects in a tree")
@app.command("ls-tree", help="List objects in a tree")
def ls(oid: str = typer.Argument(..., allow_dash=True)):
    odb = get_odb()
    oid = from_shortoid(odb, oid)
    try:
        tree = Tree.load(odb, HashInfo("md5", oid))
    except ObjectFormatError as exc:
        typer.echo(exc, err=True)
        raise typer.Exit(1) from exc
    return _ls_tree(tree)


@app.command(help="Show various types of objects")
def show(oid: str = typer.Argument(..., allow_dash=True)):
    odb = get_odb()
    oid = from_shortoid(odb, oid)
    obj = load(odb, odb.get(oid).hash_info)
    if isinstance(obj, Tree):
        return _ls_tree(obj)
    if isinstance(obj, HashFile):
        return _cat_object(odb, obj.oid)
    raise AssertionError(f"unknown object of type {type(obj)}")


@app.command(help="Summarize disk usage by an object")
def du(oid: str = typer.Argument(..., allow_dash=True)):
    odb = get_odb()
    oid = from_shortoid(odb, oid)
    obj = load(odb, odb.get(oid).hash_info)
    if not isinstance(obj, HashFile):
        raise AssertionError(f"unknown object of type {type(obj)}")

    if isinstance(obj, Tree):
        tree = obj
    else:
        tree = Tree()
        tree.add(ROOT, None, obj.hash_info)

    total = _du(odb, tree)
    print(tqdm.format_sizeof(total, suffix="B", divisor=1024))


@app.command(help="Remove object from the ODB")
def rm(oid: str = typer.Argument(..., allow_dash=True)):
    odb = get_odb()
    oid = from_shortoid(odb, oid)
    odb.delete(oid)


@app.command(help="Count objects and their disk consumption", no_args_is_help=False)
def count_objects():
    odb = get_odb()
    it = (odb.fs.size(odb.oid_to_path(oid)) for oid in odb.all())
    item = deque(enumerate(accumulate(it), 1), maxlen=1)
    count, total = item[0] if item else (0, 0)
    hsize = tqdm.format_sizeof(total, suffix="B", divisor=1024)
    print(f"{count} objects, {hsize} size")


@app.command(help="Verify objects in the database", no_args_is_help=False)
def fsck():
    odb = get_odb()
    ret = 0
    for oid in odb.all():
        try:
            odb.check(oid, check_hash=True)
        except ObjectFormatError as exc:
            ret = 1
            print(exc)
    raise typer.Exit(ret)


@app.command(help="Diff two objects in the database")
def diff(
    short_oid1,
    short_oid2: str,
    unchanged: bool = False,
    check_cache: bool = False,
    check_hash: bool = False,
):
    odb = get_odb()
    obj1 = odb.get(from_shortoid(odb, short_oid1))
    obj2 = odb.get(from_shortoid(odb, short_oid2))

    odb_check = odb.check

    def check(oid: str, check_hash: bool = check_hash):
        return not check_cache or odb_check(oid, check_hash=check_hash)

    odb.check = check
    d = _diff(load(odb, obj1.hash_info), load(odb, obj2.hash_info), odb)

    def _prepare_info(entry):
        path = posixpath.join(*entry.key) or "ROOT"
        oid = entry.oid.value
        if not oid.endswith(".dir"):
            oid = entry.oid.value[:9]
        cache_info = "" if entry.in_cache else ", missing"
        return f"{path} ({oid}{cache_info})"

    for state, changes in asdict(d, recurse=False).items():
        for change in changes:
            if not unchanged and state == "unchanged" and change.new.in_cache:
                continue
            if state == "modified":
                info1 = _prepare_info(change.old)
                info2 = _prepare_info(change.new)
                info = f"{info1} -> {info2}"
            elif state == "added":
                info = _prepare_info(change.new)
            else:
                # for unchanged, it does not matter which entry we use
                # for deleted, we should be using old entry
                info = _prepare_info(change.old)
            print(state, info, sep=": ")


@app.command(help="Check object link")
def check_link(  # noqa: C901
    path: Path = dir_file_type_no_dash_no_resolve, object_dir: Optional[Path] = None
):
    if object_dir is None:
        object_dir = Repo.discover().object_dir

    fs = LocalFileSystem()

    def get_object_inodes(path) -> dict[int, str]:
        ret = {}
        for entry in os.scandir(path):
            if entry.is_dir(follow_symlinks=False) and len(entry.name) == 2:
                for e in os.scandir(entry.path):
                    if e.is_file(follow_symlinks=False):
                        ret[e.inode()] = e.path
        return ret

    object_inodes = None
    files = [os.fspath(path)] if path.is_file() else fs.find(os.fspath(path))
    for file in files:
        try:
            info = fs.info(file)
        except OSError as e:
            if e.errno != errno.ENOENT or not os.path.islink(file):
                raise
            infos = ["broken", os.readlink(file)]
            mode = 0
        else:
            infos = ["unknown"]
            inode = info["ino"]
            if info["islink"]:
                infos = ["symlink", info["destination"]]
            elif info["nlink"] > 1:
                if object_inodes is None:
                    object_inodes = get_object_inodes(object_dir)
                if object_path := object_inodes.get(inode):
                    infos = ["hardlink", object_path]
            mode = info["mode"]
        print(stat.filemode(mode), file, *infos)


@app.command(help="Checkout from the object into a given path")
def checkout(
    oid: str,
    path: Path = typer.Argument(..., resolve_path=True),
    relink: bool = False,
    force: bool = False,
    type: list[LinkEnum] = typer.Option(["copy"]),  # noqa: A002
):
    odb = get_odb(type=[t.value for t in type])
    oid = from_shortoid(odb, oid)
    obj = load(odb, odb.get(oid).hash_info)
    with TqdmCallback(size=len(obj), desc="Checking out", unit="obj") as callback:
        _checkout(
            os.fspath(path),
            LocalFileSystem(),
            obj,
            odb,
            relink=relink,
            force=force,
            prompt=typer.confirm,
            state=odb.state,
            progress_callback=callback,
        )


index = Application(name="index")
app.add_typer(index)


def print_table(rows):
    if not rows:
        return
    indexes = [i for i, _ in enumerate(rows[0]) if any(row[i] for row in rows[1:])]
    filtered_rows = [[row[i] for i in indexes] for row in rows]
    col_widths = [max(len(str(cell)) for cell in col) for col in zip(*filtered_rows)]
    for row in filtered_rows:
        print(*(cell.ljust(col_widths[i]) for i, cell in enumerate(row)))


@index.command(name="ls", help="List objects in the index")
def index_ls(path: str = typer.Argument(""), site_cache_dir: Path = typer.Option(...)):  # noqa: C901
    index = DataIndex.open(site_cache_dir / "index" / "data" / "db.db")

    def build_row(key, info, prefix="", absolute=False):
        if not key:
            key = (posixpath.sep,)
        elif not absolute:
            key = (key[-1],)
        if info["type"] == "directory":
            key = (*key, "")

        path = posixpath.join(*key)
        size = ""
        if info["type"] != "directory" and info["size"] is not None:
            size = str(info["size"])
        entry = info["entry"]
        version_id = ""
        hash_name = ""
        hash_value = ""
        loaded = ""
        nfiles = ""
        if entry:
            if entry.meta and entry.meta:
                meta = entry.meta
                nfiles = str(meta.nfiles) if meta.nfiles is not None else ""
                version_id = meta.version_id if meta.version_id is not None else ""
            if entry.hash_info:
                hash_name = entry.hash_info.name
                hash_value = entry.hash_info.value
            if info["type"] == "directory" and entry.loaded is None:
                loaded = "no"

        return [
            "x" if info["isexec"] else "",
            size,
            version_id,
            hash_name,
            hash_value,
            loaded,
            nfiles,
            prefix + path,
        ]

    def collect_rows(start_path, prefix=""):
        if not prefix:
            info = index.info(start_path)
            yield build_row(start_path, info, prefix, absolute=True)

        entries = list(index.ls(start_path))
        entries_count = len(entries)
        for i, (key, info) in enumerate(entries):
            connector = "└── " if i == entries_count - 1 else "├── "
            yield build_row(key, info, prefix + connector)

            if info["type"] == "directory":
                extension = "    " if i == entries_count - 1 else "│   "
                yield from collect_rows(key, prefix + extension)

    path = path.strip(posixpath.sep)
    if path in ("", posixpath.curdir):
        root: tuple[str, ...] = ()
    else:
        root = tuple(path.split(posixpath.sep))
    header = ["exec", "size", "version_id", "hash", "value", "loaded", "files", ""]
    print_table([header, *collect_rows(root)])


main = typer.main.get_command(app)


if __name__ == "__main__":
    main()
