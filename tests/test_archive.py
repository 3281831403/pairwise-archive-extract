"""Contract tests for :mod:`safe_extract.archive`.

Every test builds its own archive in ``tmp_path`` (zipfile / tarfile) and
calls the module's public API.  Nothing external is read, nothing random is
used, and no test writes outside ``tmp_path``.
"""

from __future__ import annotations

import io
import stat
import tarfile
import zipfile
from pathlib import Path

import pytest

from safe_extract.archive import (
    UnsafeArchive,
    check_limits,
    check_links,
    extract,
    normalize_member,
    verify_result,
)

LIMITS = {
    "max_entries": 64,
    "max_total_size": 1 << 20,
    "max_ratio": 100,
    "max_path_len": 200,
}


def _entry(name, size=4, compressed_size=4, mode=stat.S_IFREG | 0o644,
           is_symlink=False, link_target=None):
    return {
        "name": name,
        "size": size,
        "compressed_size": compressed_size,
        "mode": mode,
        "is_symlink": is_symlink,
        "link_target": link_target,
    }


def _write_zip(path, members):
    with zipfile.ZipFile(path, "w") as zf:
        for name, data in members:
            zf.writestr(name, data)
    return path


def _write_tar(path, members):
    with tarfile.open(path, "w") as tf:
        for name, data in members:
            info = tarfile.TarInfo(name)
            info.size = len(data)
            info.mode = 0o644
            tf.addfile(info, io.BytesIO(data))
    return path


def _dir_is_empty(path):
    return (not path.exists()) or (path.is_dir() and not any(path.iterdir()))


# --------------------------------------------------------------------------
# Defect 1 -- member names are not normalized before landing on disk.
# --------------------------------------------------------------------------


def test_rejects_parent_traversal():
    for name in ("../evil.txt", "pkg/../../evil.txt", "a/./../evil.txt"):
        with pytest.raises(UnsafeArchive):
            normalize_member(name)


def test_rejects_absolute_path():
    for name in ("/etc/passwd", "C:/Windows/evil.txt", "c:/temp/evil.txt"):
        with pytest.raises(UnsafeArchive):
            normalize_member(name)


def test_rejects_backslash():
    for name in ("dir\\evil.txt", "..\\evil.txt", "pkg\\sub\\data.txt"):
        with pytest.raises(UnsafeArchive):
            normalize_member(name)


# --------------------------------------------------------------------------
# Defect 2 -- symlink / hardlink targets may point outside dest.
# --------------------------------------------------------------------------


def test_rejects_symlink_escape(tmp_path):
    dest = tmp_path / "dest"
    dest.mkdir()
    entries = [
        _entry("data.txt", size=4, compressed_size=4),
        _entry("link", size=0, compressed_size=0, mode=stat.S_IFLNK | 0o777,
               is_symlink=True, link_target="../../etc/passwd"),
    ]
    with pytest.raises(UnsafeArchive):
        check_links(entries, str(dest))


def test_rejects_hardlink_escape(tmp_path):
    dest = tmp_path / "dest"
    dest.mkdir()
    entries = [
        _entry("hard", size=0, compressed_size=0, mode=stat.S_IFREG | 0o644,
               is_symlink=False, link_target="../outside/secret.txt"),
    ]
    with pytest.raises(UnsafeArchive):
        check_links(entries, str(dest))


def test_rejects_setuid(tmp_path):
    dest = tmp_path / "dest"
    dest.mkdir()
    entries = [
        _entry("tool", size=8, compressed_size=8,
               mode=stat.S_IFREG | stat.S_ISUID | 0o755),
    ]
    with pytest.raises(UnsafeArchive):
        check_links(entries, str(dest))


# --------------------------------------------------------------------------
# Defect 3 -- only per-file size is bounded (zip bomb).
# --------------------------------------------------------------------------


def test_rejects_entry_count():
    entries = [_entry("f%d.txt" % i) for i in range(5)]
    limits = {"max_entries": 3, "max_total_size": 1 << 20,
              "max_ratio": 1000, "max_path_len": 200}
    with pytest.raises(UnsafeArchive):
        check_limits(entries, limits)


def test_rejects_total_size():
    entries = [_entry("f%d.txt" % i, size=100, compressed_size=100)
               for i in range(3)]
    limits = {"max_entries": 10, "max_total_size": 200,
              "max_ratio": 1000, "max_path_len": 200}
    with pytest.raises(UnsafeArchive):
        check_limits(entries, limits)


def test_rejects_compression_ratio():
    entries = [_entry("bomb.bin", size=10_000_000, compressed_size=1_000)]
    limits = {"max_entries": 10, "max_total_size": 1 << 30,
              "max_ratio": 100, "max_path_len": 200}
    with pytest.raises(UnsafeArchive):
        check_limits(entries, limits)


def test_rejects_path_too_long():
    name = "/".join(["segment%02d" % i for i in range(20)]) + "/payload.txt"
    assert len(name) > 200
    entries = [_entry(name, size=4, compressed_size=4)]
    limits = {"max_entries": 10, "max_total_size": 1 << 20,
              "max_ratio": 100, "max_path_len": 200}
    with pytest.raises(UnsafeArchive):
        check_limits(entries, limits)


# --------------------------------------------------------------------------
# Defect 4 -- extraction streams to disk and lets duplicates overwrite.
# --------------------------------------------------------------------------


def test_duplicate_member_last_wins(tmp_path):
    archive = _write_tar(
        tmp_path / "dup.tar",
        [("dup.txt", b"first"), ("dup.txt", b"second")],
    )
    dest = tmp_path / "dup-out"
    extracted = extract(str(archive), str(dest), LIMITS)
    assert "dup.txt" in extracted
    assert (dest / "dup.txt").read_bytes() == b"second"


def test_failed_extract_leaves_empty_dest(tmp_path):
    archive = _write_tar(
        tmp_path / "bad.tar",
        [("ok.txt", b"fine"), ("../escape.txt", b"pwned")],
    )
    dest = tmp_path / "bad-out"
    with pytest.raises(UnsafeArchive):
        extract(str(archive), str(dest), LIMITS)
    assert _dir_is_empty(dest)


# --------------------------------------------------------------------------
# Defect 5 -- no post-extraction recheck of real paths / case folding.
# --------------------------------------------------------------------------


def test_rejects_case_conflict(tmp_path):
    archive = _write_zip(
        tmp_path / "case.zip",
        [("A.txt", b"upper"), ("a.txt", b"lower")],
    )
    dest = tmp_path / "case-out"
    with pytest.raises(UnsafeArchive):
        extract(str(archive), str(dest), LIMITS)


def test_rejects_disguised_escape_after_extract(tmp_path):
    dest = tmp_path / "verify-out"
    dest.mkdir()
    (dest / "keep.txt").write_bytes(b"keep")
    (dest / "extra.txt").write_bytes(b"undeclared")
    extracted = ["keep.txt", "../escape.txt"]
    with pytest.raises(UnsafeArchive):
        verify_result(str(dest), extracted, LIMITS)


# --------------------------------------------------------------------------
# Happy path -- a plain archive must still extract.
# --------------------------------------------------------------------------


def test_extracts_normal_zip(tmp_path):
    archive = _write_zip(
        tmp_path / "normal.zip",
        [("pkg/data.txt", b"hello world"), ("pkg/sub/notes.txt", b"note")],
    )
    dest = tmp_path / "normal-out"
    extracted = extract(str(archive), str(dest), LIMITS)
    assert sorted(extracted) == ["pkg/data.txt", "pkg/sub/notes.txt"]
    assert (dest / "pkg" / "data.txt").read_bytes() == b"hello world"
    assert (dest / "pkg" / "sub" / "notes.txt").read_bytes() == b"note"
