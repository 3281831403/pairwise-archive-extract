"""Safe archive extraction: validation, limits, atomic landing, re-check.

The public contract is documented on each function below; ``tests/test_archive.py``
is the executable specification.  Only the standard library is used.
"""

from __future__ import annotations

import os
import re
import shutil
import stat
import tarfile
import tempfile
import zipfile
from pathlib import PurePosixPath

__all__ = [
    "UnsafeArchive",
    "normalize_member",
    "check_limits",
    "check_links",
    "extract",
    "verify_result",
]


class UnsafeArchive(Exception):
    """Raised when an archive cannot be inspected or extracted safely."""


_DRIVE_RE = re.compile(r"^[A-Za-z]:")
_CHUNK = 64 * 1024
_MAX_LINK_TARGET = 64 * 1024

_SPECIAL_TYPES = (
    stat.S_IFBLK,
    stat.S_IFCHR,
    stat.S_IFIFO,
    stat.S_IFSOCK,
)

_EVIL_BITS = stat.S_ISUID | stat.S_ISGID | stat.S_ISVTX


# ---------------------------------------------------------------------------
# Name normalization
# ---------------------------------------------------------------------------


def normalize_member(name: str) -> PurePosixPath:
    """Turn one raw archive member name into a safe relative POSIX path.

    Rejects absolute names, Windows drive letters, ``..`` segments, NUL bytes,
    backslashes, ``~`` prefixes and names that normalize to nothing.  Empty and
    ``.`` segments are dropped and trailing separators removed.
    """
    if not isinstance(name, str):
        raise UnsafeArchive("member name is not text: %r" % (name,))
    if "\x00" in name:
        raise UnsafeArchive("member name contains NUL: %r" % (name,))
    if "\\" in name:
        raise UnsafeArchive("member name contains a backslash: %r" % (name,))
    if name.startswith("/"):
        raise UnsafeArchive("member name is absolute: %r" % (name,))
    if _DRIVE_RE.match(name):
        raise UnsafeArchive("member name carries a drive letter: %r" % (name,))
    if name.startswith("~"):
        raise UnsafeArchive("member name uses home shorthand: %r" % (name,))

    parts = []
    for segment in name.split("/"):
        if segment in ("", "."):
            continue
        if segment == "..":
            raise UnsafeArchive("member name traverses upwards: %r" % (name,))
        parts.append(segment)

    if not parts:
        raise UnsafeArchive("member name is empty after normalization: %r" % (name,))

    result = PurePosixPath(*parts)
    if result.is_absolute():
        raise UnsafeArchive("member name is absolute: %r" % (name,))
    return result


# ---------------------------------------------------------------------------
# Aggregate limits
# ---------------------------------------------------------------------------


def check_limits(entries: list[dict], limits: dict) -> None:
    """Validate entry-count / total-size / ratio / path-length bounds."""
    limits = limits or {}

    total_size = sum(int(entry.get("size") or 0) for entry in entries)
    total_compressed = sum(int(entry.get("compressed_size") or 0) for entry in entries)

    max_entries = limits.get("max_entries")
    if max_entries is not None and len(entries) > max_entries:
        raise UnsafeArchive(
            "archive has %d entries, limit is %d" % (len(entries), max_entries)
        )

    max_total_size = limits.get("max_total_size")
    if max_total_size is not None and total_size > max_total_size:
        raise UnsafeArchive(
            "archive expands to %d bytes, limit is %d"
            % (total_size, max_total_size)
        )

    max_ratio = limits.get("max_ratio")
    if (
        max_ratio is not None
        and total_compressed > 0
        and total_size > max_ratio * total_compressed
    ):
        raise UnsafeArchive(
            "compression ratio %r exceeds limit %r"
            % (total_size / total_compressed, max_ratio)
        )

    max_path_len = limits.get("max_path_len")
    if max_path_len is not None:
        longest = max((len(str(entry.get("name", ""))) for entry in entries), default=0)
        if longest > max_path_len:
            raise UnsafeArchive(
                "member path of %d characters exceeds limit %d"
                % (longest, max_path_len)
            )


# ---------------------------------------------------------------------------
# Link / special-file validation
# ---------------------------------------------------------------------------


def check_links(entries: list[dict], dest: str) -> None:
    """Reject link members that escape ``dest`` and every special file."""
    for entry in entries:
        mode = int(entry.get("mode") or 0)
        if stat.S_IFMT(mode) in _SPECIAL_TYPES:
            raise UnsafeArchive(
                "member %r is a device, FIFO or socket" % (entry.get("name"),)
            )
        if mode & _EVIL_BITS:
            raise UnsafeArchive(
                "member %r carries a setuid/setgid/sticky bit" % (entry.get("name"),)
            )

        target = entry.get("link_target")
        if target is None:
            continue
        if not isinstance(target, str):
            raise UnsafeArchive("link target is not text: %r" % (target,))
        if not target or "\x00" in target:
            raise UnsafeArchive("link target is empty or contains NUL: %r" % (target,))
        if "\\" in target or _DRIVE_RE.match(target):
            # A drive-qualified or backslashed target escapes on Windows even
            # though os.path.join would keep it under ``dest`` here.
            raise UnsafeArchive(
                "link target is a Windows-style path: %r" % (target,)
            )

        name = str(entry.get("name", ""))
        parent = PurePosixPath(name).parent
        base = os.path.join(dest, *parent.parts) if parent.parts else dest
        candidate = os.path.join(base, target)
        if not _is_within(candidate, dest):
            raise UnsafeArchive(
                "link %r points outside the destination: %r" % (name, target)
            )


# ---------------------------------------------------------------------------
# Extraction
# ---------------------------------------------------------------------------


def extract(archive_path: str, dest: str, limits: dict) -> list[str]:
    """Safely extract ``archive_path`` into ``dest``; return written names."""
    dest = os.path.abspath(dest)

    if os.path.islink(dest):
        raise UnsafeArchive("destination is a symlink: %r" % (dest,))
    if os.path.lexists(dest) and not os.path.isdir(dest):
        raise UnsafeArchive("destination is not a directory: %r" % (dest,))

    kind, entries = _enumerate(archive_path)

    # Everything below happens before the first byte is written.
    check_limits(entries, limits)
    check_links(entries, dest)
    _reject_name_conflicts(entries)

    names = sorted({str(entry["name"]) for entry in entries if not entry["is_dir"]})

    parent = os.path.dirname(dest)
    os.makedirs(parent, exist_ok=True)

    staging = tempfile.mkdtemp(prefix=".safe-extract-", dir=parent)
    backup = None
    landed = False
    try:
        _write_members(archive_path, kind, staging, entries, limits)
        # Full re-check of the staged tree; destination stays untouched if
        # anything drifts.
        verify_result(staging, names, limits)
        backup = _install(staging, dest)
        staging = None
        landed = True
        # Re-check after landing: real paths and the final file inventory.
        verify_result(dest, names, limits)
    except BaseException:
        if landed:
            _rollback(dest, backup)
        raise
    finally:
        if staging is not None:
            shutil.rmtree(staging, ignore_errors=True)
        if backup is not None:
            shutil.rmtree(backup, ignore_errors=True)

    return names


def verify_result(dest: str, extracted: list[str], limits: dict) -> None:
    """Re-inspect the written tree and reject any drift from the declaration."""
    dest = os.path.abspath(dest)
    if os.path.islink(dest) or not os.path.isdir(dest):
        raise UnsafeArchive("destination is not a real directory: %r" % (dest,))

    declared = []
    for name in extracted:
        if not isinstance(name, str):
            raise UnsafeArchive("declared name is not text: %r" % (name,))
        declared.append(str(normalize_member(name)))

    # Declared names must be unique up to case folding.
    _reject_case_collisions(declared, "declared")

    on_disk = _walk(dest)
    _reject_case_collisions(on_disk, "on disk")

    for name in declared:
        path = _join(dest, name)
        if not _is_within(path, dest):
            raise UnsafeArchive("declared member escapes destination: %r" % (name,))
        if not os.path.lexists(path):
            raise UnsafeArchive("declared member is missing on disk: %r" % (name,))

    for name in on_disk:
        path = _join(dest, name)
        if not _is_within(path, dest):
            raise UnsafeArchive("on-disk member escapes destination: %r" % (name,))

    if {name.casefold() for name in declared} != {
        name.casefold() for name in on_disk
    }:
        missing = sorted(
            {name.casefold() for name in declared}
            - {name.casefold() for name in on_disk}
        )
        extra = sorted(
            {name.casefold() for name in on_disk}
            - {name.casefold() for name in declared}
        )
        raise UnsafeArchive(
            "extracted tree does not match the declaration "
            "(missing=%r, undeclared=%r)" % (missing, extra)
        )

    limits = limits or {}

    max_entries = limits.get("max_entries")
    if max_entries is not None and len(on_disk) > max_entries:
        raise UnsafeArchive(
            "extracted tree has %d files, limit is %d"
            % (len(on_disk), max_entries)
        )

    max_path_len = limits.get("max_path_len")
    if max_path_len is not None:
        longest = max(
            (len(name) for name in list(declared) + list(on_disk)), default=0
        )
        if longest > max_path_len:
            raise UnsafeArchive(
                "path of %d characters exceeds limit %d" % (longest, max_path_len)
            )

    max_total_size = limits.get("max_total_size")
    if max_total_size is not None:
        total = 0
        for name in on_disk:
            st = os.lstat(_join(dest, name))
            if stat.S_ISREG(st.st_mode):
                total += st.st_size
        if total > max_total_size:
            raise UnsafeArchive(
                "extracted tree is %d bytes, limit is %d"
                % (total, max_total_size)
            )


# ---------------------------------------------------------------------------
# Enumeration
# ---------------------------------------------------------------------------


def _enumerate(archive_path: str) -> tuple[str, list[dict]]:
    try:
        if not os.path.isfile(archive_path):
            raise UnsafeArchive("archive does not exist: %r" % (archive_path,))
        if zipfile.is_zipfile(archive_path):
            return "zip", _enumerate_zip(archive_path)
        if tarfile.is_tarfile(archive_path):
            return "tar", _enumerate_tar(archive_path)
    except (OSError, zipfile.BadZipFile) as exc:
        raise UnsafeArchive("cannot inspect archive: %s" % (exc,)) from exc
    raise UnsafeArchive("not a zip or tar archive: %r" % (archive_path,))


def _enumerate_zip(archive_path: str) -> list[dict]:
    entries = []
    try:
        with zipfile.ZipFile(archive_path) as zf:
            for info in zf.infolist():
                name = str(normalize_member(info.filename))
                is_dir = info.is_dir() or info.filename.endswith("/")
                mode = (info.external_attr >> 16) & 0xFFFF
                is_symlink = bool(not is_dir and stat.S_ISLNK(mode))
                link_target = None
                if is_symlink:
                    with zf.open(info) as fp:
                        data = fp.read(_MAX_LINK_TARGET + 1)
                    if len(data) > _MAX_LINK_TARGET:
                        raise UnsafeArchive(
                            "symlink target is unreasonably long: %r" % (name,)
                        )
                    link_target = data.decode("utf-8", "surrogateescape")
                entries.append(
                    {
                        "name": name,
                        "size": int(info.file_size),
                        "compressed_size": int(info.compress_size),
                        "mode": mode,
                        "is_symlink": is_symlink,
                        "link_target": link_target,
                        "is_dir": is_dir,
                        "_member": info,
                    }
                )
    except (zipfile.BadZipFile, OSError, RuntimeError) as exc:
        raise UnsafeArchive("cannot read zip archive: %s" % (exc,)) from exc
    return entries


def _enumerate_tar(archive_path: str) -> list[dict]:
    entries = []
    try:
        archive_size = max(int(os.path.getsize(archive_path)), 1)
        with tarfile.open(archive_path, "r:*") as tf:
            members = tf.getmembers()
            total_regular = sum(m.size for m in members if m.isreg())
            for member in members:
                name = str(normalize_member(member.name))
                is_symlink = member.issym()
                is_hardlink = member.islnk()
                link_target = member.linkname if (is_symlink or is_hardlink) else None

                if member.isreg() and total_regular > 0:
                    # tar offers no per-member compressed size; attribute the
                    # on-disk archive size proportionally so the ratio check
                    # still catches compressed-tar bombs.
                    compressed = max(
                        1, int(member.size * archive_size / total_regular)
                    )
                else:
                    compressed = 0

                entries.append(
                    {
                        "name": name,
                        "size": int(member.size),
                        "compressed_size": compressed,
                        "mode": _tar_mode(member),
                        "is_symlink": is_symlink,
                        "link_target": link_target,
                        "is_dir": member.isdir(),
                        "_member": member,
                    }
                )
    except (tarfile.TarError, OSError) as exc:
        raise UnsafeArchive("cannot read tar archive: %s" % (exc,)) from exc
    return entries


def _tar_mode(member: tarfile.TarInfo) -> int:
    if member.issym():
        kind = stat.S_IFLNK
    elif member.isdir():
        kind = stat.S_IFDIR
    elif member.ischr():
        kind = stat.S_IFCHR
    elif member.isblk():
        kind = stat.S_IFBLK
    elif member.isfifo():
        kind = stat.S_IFIFO
    else:
        kind = stat.S_IFREG
    return kind | (int(member.mode) & 0o7777)


# ---------------------------------------------------------------------------
# Writing
# ---------------------------------------------------------------------------


def _write_members(
    archive_path: str, kind: str, root: str, entries: list[dict], limits: dict
) -> None:
    max_total = (limits or {}).get("max_total_size")
    written_total = 0

    if kind == "zip":
        with zipfile.ZipFile(archive_path) as zf:
            for entry in entries:
                if entry["is_dir"]:
                    continue
                target = _join(root, entry["name"])
                if entry["is_symlink"]:
                    _ensure_parent(target)
                    _replace_path(target)
                    _create_symlink(entry["link_target"] or "", target)
                    continue
                _ensure_parent(target)
                _replace_path(target)
                with zf.open(entry["_member"]) as src:
                    written_total = _copy_member(
                        src, target, entry["size"], written_total, max_total
                    )
        return

    with tarfile.open(archive_path, "r:*") as tf:
        for entry in entries:
            if entry["is_dir"]:
                continue
            target = _join(root, entry["name"])
            if entry["is_symlink"]:
                _ensure_parent(target)
                _replace_path(target)
                _create_symlink(entry["link_target"] or "", target)
                continue
            if entry["link_target"] is not None:
                parent = PurePosixPath(str(entry["name"])).parent
                base = os.path.join(root, *parent.parts) if parent.parts else root
                source = os.path.join(base, entry["link_target"])
                if not _is_within(source, root) or not os.path.isfile(source):
                    raise UnsafeArchive(
                        "hard link %r has no in-tree target: %r"
                        % (entry["name"], entry["link_target"])
                    )
                _ensure_parent(target)
                _replace_path(target)
                try:
                    os.link(source, target)
                except OSError as exc:
                    raise UnsafeArchive(
                        "cannot create hard link %r: %s" % (entry["name"], exc)
                    ) from exc
                continue
            src = tf.extractfile(entry["_member"])
            if src is None:
                raise UnsafeArchive("cannot read member %r" % (entry["name"],))
            _ensure_parent(target)
            _replace_path(target)
            try:
                written_total = _copy_member(
                    src, target, entry["size"], written_total, max_total
                )
            finally:
                src.close()


def _copy_member(src, target: str, expected: int, written_total: int, max_total):
    count = 0
    try:
        with open(target, "wb") as out:
            while True:
                chunk = src.read(_CHUNK)
                if not chunk:
                    break
                count += len(chunk)
                if count > expected:
                    raise UnsafeArchive(
                        "member %r expands past its declared size" % (target,)
                    )
                if max_total is not None and written_total + count > max_total:
                    raise UnsafeArchive("archive expands past the total size limit")
                out.write(chunk)
    except OSError as exc:
        raise UnsafeArchive("cannot write %r: %s" % (target, exc)) from exc
    return written_total + count


def _ensure_parent(target: str) -> None:
    parent = os.path.dirname(target)
    try:
        os.makedirs(parent, exist_ok=True)
    except OSError as exc:
        raise UnsafeArchive("cannot create directory %r: %s" % (parent, exc)) from exc


def _create_symlink(target: str, link_path: str) -> None:
    try:
        os.symlink(target, link_path)
    except (OSError, NotImplementedError) as exc:
        raise UnsafeArchive("cannot create symlink %r: %s" % (link_path, exc)) from exc


def _replace_path(target: str) -> None:
    if not os.path.lexists(target):
        return
    try:
        if os.path.isdir(target) and not os.path.islink(target):
            shutil.rmtree(target)
        else:
            os.unlink(target)
    except OSError as exc:
        raise UnsafeArchive("cannot replace %r: %s" % (target, exc)) from exc


def _install(staging: str, dest: str) -> str | None:
    """Move ``staging`` onto ``dest`` atomically; return the backed-up tree.

    A pre-existing ``dest`` is renamed aside rather than deleted so a failed
    post-landing check can be rolled back.  The caller owns the backup.
    """
    backup = None
    if os.path.lexists(dest):
        if os.path.islink(dest) or not os.path.isdir(dest):
            raise UnsafeArchive("destination is not a real directory: %r" % (dest,))
        backup = tempfile.mkdtemp(
            prefix=".safe-extract-old-", dir=os.path.dirname(dest)
        )
        os.rmdir(backup)
        os.rename(dest, backup)

    try:
        os.rename(staging, dest)
    except BaseException:
        if backup is not None and not os.path.lexists(dest):
            os.rename(backup, dest)
        raise
    return backup


def _rollback(dest: str, backup: str | None) -> None:
    """Discard the freshly landed tree and restore ``backup`` if there was one."""
    shutil.rmtree(dest, ignore_errors=True)
    if backup is not None and not os.path.lexists(dest):
        try:
            os.rename(backup, dest)
        except OSError:
            pass


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


def _join(root: str, name: str) -> str:
    return os.path.join(root, *PurePosixPath(str(name)).parts)


def _canonical(path: str) -> str:
    return os.path.normpath(os.path.realpath(path)).casefold()


def _is_within(path: str, root: str) -> bool:
    """Case-insensitive containment on fully resolved absolute paths."""
    resolved = _canonical(path)
    base = _canonical(root)
    if resolved == base:
        return True
    prefix = base if base.endswith(os.sep) else base + os.sep
    return resolved.startswith(prefix)


def _walk(root: str) -> list[str]:
    """List non-directory entries (files and symlinks) as relative POSIX names."""
    found = []
    stack = [("", root)]
    while stack:
        rel, full = stack.pop()
        try:
            with os.scandir(full) as iterator:
                for item in iterator:
                    name = item.name
                    if name in (".", ".."):
                        continue
                    relname = rel + "/" + name if rel else name
                    if item.is_symlink():
                        found.append(relname)
                    elif item.is_dir(follow_symlinks=False):
                        stack.append((relname, item.path))
                    else:
                        found.append(relname)
        except OSError as exc:
            raise UnsafeArchive("cannot inspect %r: %s" % (full, exc)) from exc
    return sorted(found)


def _reject_case_collisions(names: list[str], where: str) -> None:
    seen = {}
    for name in names:
        key = name.casefold()
        if key in seen and seen[key] != name:
            raise UnsafeArchive(
                "case-insensitive collision %s: %r vs %r"
                % (where, seen[key], name)
            )
        seen[key] = name


def _reject_name_conflicts(entries: list[dict]) -> None:
    """Reject case-folded twins and file/directory collisions.

    Exact duplicate names are allowed: the last member wins.
    """
    claims: dict[str, tuple[str, bool]] = {}
    for entry in entries:
        path = PurePosixPath(str(entry["name"]))
        parts = path.parts
        for index in range(1, len(parts)):
            _claim(claims, "/".join(parts[:index]), directory=True)
        _claim(claims, str(path), directory=bool(entry["is_dir"]))


def _claim(claims: dict[str, tuple[str, bool]], name: str, directory: bool) -> None:
    key = name.casefold()
    existing = claims.get(key)
    if existing is None:
        claims[key] = (name, directory)
        return
    existing_name, existing_is_dir = existing
    if existing_name != name:
        raise UnsafeArchive(
            "case-insensitive member collision: %r vs %r"
            % (existing_name, name)
        )
    if existing_is_dir != directory:
        raise UnsafeArchive(
            "member %r is declared as both file and directory" % (name,)
        )
