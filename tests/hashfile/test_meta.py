from datetime import datetime, timezone

import pytest

from dvc_data.hashfile.meta import Meta


def test_from_info_http_last_modified():
    info = {
        "type": "file",
        "size": 123,
        "Last-Modified": "Wed, 21 Oct 2015 07:28:00 GMT",
    }
    meta = Meta.from_info(info, protocol="https")
    expected = datetime(2015, 10, 21, 7, 28, 0, tzinfo=timezone.utc).timestamp()
    assert meta.mtime == expected


def test_from_info_http_mtime_takes_precedence_over_last_modified():
    info = {
        "type": "file",
        "size": 123,
        "mtime": 1000.0,
        "Last-Modified": "Wed, 21 Oct 2015 07:28:00 GMT",
    }
    meta = Meta.from_info(info, protocol="http")
    assert meta.mtime == 1000.0


def test_from_info_http_no_last_modified():
    info = {"type": "file", "size": 123}
    meta = Meta.from_info(info, protocol="https")
    assert meta.mtime is None


@pytest.mark.parametrize("protocol", ["s3", "gs", "azure", "local", None])
def test_from_info_last_modified_ignored_for_non_http(protocol):
    info = {
        "type": "file",
        "size": 123,
        "Last-Modified": "Wed, 21 Oct 2015 07:28:00 GMT",
    }
    meta = Meta.from_info(info, protocol=protocol)
    assert meta.mtime is None
