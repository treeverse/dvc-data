import logging
import os
import re
import sys
from typing import Any, BinaryIO, ClassVar, Optional, Union

import fsspec
from tqdm import tqdm

logger = logging.getLogger(__name__)


def env2bool(var, undefined=False):
    """
    undefined: return value if env var is unset
    """
    var = os.getenv(var, None)
    if var is None:
        return undefined
    return bool(re.search("1|y|yes|true", var, flags=re.I))


class Tqdm(tqdm):
    """
    maximum-compatibility tqdm-based progressbars
    """

    BAR_FMT_DEFAULT = (
        "{percentage:3.0f}% {desc}|{bar}|"
        "{postfix[info]}{n_fmt}/{total_fmt}"
        " [{elapsed}<{remaining}, {rate_fmt:>11}]"
    )
    # nested bars should have fixed bar widths to align nicely
    BAR_FMT_DEFAULT_NESTED = (
        "{percentage:3.0f}%|{bar:10}|{desc:{ncols_desc}.{ncols_desc}}"
        "{postfix[info]}{n_fmt}/{total_fmt}"
        " [{elapsed}<{remaining}, {rate_fmt:>11}]"
    )
    BAR_FMT_NOTOTAL = "{desc}{bar:b}|{postfix[info]}{n_fmt} [{elapsed}, {rate_fmt:>11}]"
    BYTES_DEFAULTS: ClassVar[dict[str, Any]] = {
        "unit": "B",
        "unit_scale": True,
        "unit_divisor": 1024,
        "miniters": 1,
    }

    # always set in __init__, narrower than tqdm's `str | Mapping | None`
    postfix: dict[str, Any]
    bar_format: str

    def __init__(
        self,
        iterable=None,
        disable=None,
        level=logging.ERROR,
        desc=None,
        leave=False,
        bar_format=None,
        bytes=False,  # noqa: A002
        file=None,
        total=None,
        postfix=None,
        **kwargs,
    ):
        """
        bytes   : shortcut for
            `unit='B', unit_scale=True, unit_divisor=1024, miniters=1`
        desc  : persists after `close()`
        level  : effective logging level for determining `disable`;
            used only if `disable` is unspecified
        disable  : If (default: None) or False,
            will be determined by logging level.
            May be overridden to `True` due to non-TTY status.
            Skip override by specifying env var `DVC_IGNORE_ISATTY`.
        kwargs  : anything accepted by `tqdm.tqdm()`
        """
        kwargs = kwargs.copy()
        if bytes:
            kwargs = {**self.BYTES_DEFAULTS, **kwargs}
        else:
            kwargs.setdefault("unit_scale", total > 999 if total else True)
        if file is None:
            file = sys.stderr
        # auto-disable based on `logger.level`
        if not disable:
            disable = logger.getEffectiveLevel() > level
        # auto-disable based on TTY
        if (
            not disable
            and not env2bool("DVC_IGNORE_ISATTY")
            and hasattr(file, "isatty")
        ):
            disable = not file.isatty()
        super().__init__(
            iterable=iterable,
            disable=disable,
            leave=leave,
            desc=desc,
            bar_format="!",
            lock_args=(False,),
            total=total,
            **kwargs,
        )
        self.postfix = postfix or {"info": ""}
        if bar_format is None:
            if self.__len__():
                self.bar_format = (
                    self.BAR_FMT_DEFAULT_NESTED if self.pos else self.BAR_FMT_DEFAULT
                )
            else:
                self.bar_format = self.BAR_FMT_NOTOTAL
        else:
            self.bar_format = bar_format
        self.refresh()

    def close(self):
        self.postfix["info"] = ""
        # remove ETA (either unknown or zero); remove completed bar
        self.bar_format = self.bar_format.replace("<{remaining}", "").replace(
            "|{bar:10}|", " "
        )
        super().close()

    @property
    def format_dict(self):
        """inject `ncols_desc` to fill the display width (`ncols`)"""
        d = super().format_dict
        ncols = d["ncols"] or 80
        # assumes `bar_format` has max one of ("ncols_desc" & "ncols_info")

        meter = self.format_meter(  # type: ignore[call-arg]
            ncols_desc=1, ncols_info=1, **d
        )
        ncols_left = ncols - len(meter) + 1
        ncols_left = max(ncols_left, 0)
        if ncols_left:
            d["ncols_desc"] = d["ncols_info"] = ncols_left
        else:
            # work-around for zero-width description
            d["ncols_desc"] = d["ncols_info"] = 1
            d["prefix"] = ""
        return d


class TqdmCallback(fsspec.callbacks.TqdmCallback):
    def __init__(
        self,
        size: Optional[int] = None,
        value: int = 0,
        progress_bar: Optional["tqdm"] = None,
        tqdm_cls: Optional[type["tqdm"]] = None,
        **tqdm_kwargs,
    ):
        tqdm_kwargs.pop("total", None)
        super().__init__(
            tqdm_kwargs=tqdm_kwargs, tqdm_cls=tqdm_cls or Tqdm, size=size, value=value
        )
        if progress_bar is None:
            self.tqdm = progress_bar

    def branched(self, path_1: "Union[str, BinaryIO]", path_2: str, **kwargs):
        desc = path_1 if isinstance(path_1, str) else path_2
        return TqdmCallback(bytes=True, desc=desc)
