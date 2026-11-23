from typing import Any, ClassVar, Optional

from attrs import define, field, fields_dict
from dvc_objects.fs.utils import is_exec


@define(unsafe_hash=True)
class Meta:
    PARAM_ISDIR: ClassVar[str] = "isdir"
    PARAM_SIZE: ClassVar[str] = "size"
    PARAM_NFILES: ClassVar[str] = "nfiles"
    PARAM_ISEXEC: ClassVar[str] = "isexec"
    PARAM_VERSION_ID: ClassVar[str] = "version_id"
    PARAM_ETAG: ClassVar[str] = "etag"
    PARAM_CHECKSUM: ClassVar[str] = "checksum"
    PARAM_MD5: ClassVar[str] = "md5"
    PARAM_INODE: ClassVar[str] = "inode"
    PARAM_MTIME: ClassVar[str] = "mtime"
    PARAM_REMOTE: ClassVar[str] = "remote"

    fields: ClassVar[list[str]]

    isdir: bool = False
    size: Optional[int] = None
    nfiles: Optional[int] = None
    isexec: bool = False
    version_id: Optional[str] = None
    etag: Optional[str] = None
    checksum: Optional[str] = None
    md5: Optional[str] = None
    inode: Optional[int] = None
    mtime: Optional[float] = None

    remote: Optional[str] = field(default=None, eq=False)

    is_link: bool = field(default=False, eq=False)
    destination: Optional[str] = field(default=None, eq=False)
    nlink: int = field(default=1, eq=False)

    @classmethod
    def from_info(cls, info: dict[str, Any], protocol: Optional[str] = None) -> "Meta":
        etag = info.get("etag")
        checksum = info.get("checksum")

        if protocol == "azure" and etag and not etag.startswith('"'):
            etag = f'"{etag}"'
        if protocol == "s3" and "ETag" in info:
            etag = info["ETag"].strip('"')
        elif protocol == "gs" and "etag" in info:
            import base64

            etag = base64.b64decode(info["etag"]).hex()
        elif (
            protocol
            and protocol.startswith("http")
            and ("ETag" in info or "Content-MD5" in info)
        ):
            checksum = info.get("ETag") or info.get("Content-MD5")

        mtime = info.get("mtime")
        if mtime is None and protocol and protocol.startswith("http"):
            last_modified = info.get("Last-Modified")
            if last_modified:
                from email.utils import parsedate_to_datetime

                mtime = parsedate_to_datetime(last_modified).timestamp()

        version_id = info.get("version_id")
        if protocol == "s3" and "VersionId" in info:
            version_id = info.get("VersionId")
        elif protocol == "gs" and "generation" in info:
            version_id = info.get("generation")

        return Meta(
            info["type"] == "directory",
            info.get("size"),
            None,
            is_exec(info.get("mode", 0)),
            version_id,
            etag,
            checksum,
            info.get("md5"),
            info.get("ino"),
            mtime,
            info.get("remote"),
            info.get("islink", False),
            info.get("destination"),
            info.get("nlink", 1),
        )

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "Meta":
        kwargs = {}
        for field_ in cls.fields:
            if field_ in d:
                kwargs[field_] = d[field_]
        return cls(**kwargs)

    def to_dict(self) -> dict[str, Any]:
        ret: dict[str, Any] = {}

        if self.isdir:
            ret[self.PARAM_ISDIR] = self.isdir

        if self.size is not None:
            ret[self.PARAM_SIZE] = self.size

        if self.nfiles is not None:
            ret[self.PARAM_NFILES] = self.nfiles

        if self.isexec:
            ret[self.PARAM_ISEXEC] = self.isexec

        if self.version_id:
            ret[self.PARAM_VERSION_ID] = self.version_id

        if self.etag:
            ret[self.PARAM_ETAG] = self.etag

        if self.checksum:
            ret[self.PARAM_CHECKSUM] = self.checksum

        if self.md5:
            ret[self.PARAM_MD5] = self.md5

        if self.remote:
            ret[self.PARAM_REMOTE] = self.remote

        return ret


Meta.fields = list(fields_dict(Meta))
