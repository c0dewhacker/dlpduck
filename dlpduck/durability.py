"""Writing a file so that a crash can't leave it half-written.

Most of this system only ever appends, so an unclean shutdown costs at
most the record in flight and the readers all tolerate a truncated final
line. A handful of files aren't like that — a whole audit partition being
rewritten by a redaction, the trim checkpoint that explains a retention
delete, a spooled plugin event, the metadata beside a failed job — and
for those a plain `write_text` has two gaps worth closing:

- **Atomicity.** `write_text` truncates first. A crash between the
  truncate and the write leaves an empty or partial file where a complete
  one used to be.
- **Durability.** `write_text` returns once the data is in the page
  cache. A crash seconds later loses it, even though the call succeeded —
  which matters when the very next thing the caller does is delete the
  data this file accounts for.

Same-directory temp file, fsync, rename, fsync the directory. The reader
sees either the old contents or the new ones, and once this returns the
new ones are on the disk.
"""

from __future__ import annotations

import os
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path


def write_atomically(path: Path, content: str, *, encoding: str = "utf-8") -> None:
    path = Path(path)
    fd, tmp_name = tempfile.mkstemp(dir=str(path.parent), prefix=path.name, suffix=".tmp")
    tmp = Path(tmp_name)
    try:
        with os.fdopen(fd, "w", encoding=encoding) as f:
            f.write(content)
            f.flush()
            os.fsync(f.fileno())
        # mkstemp is 0600; keep whatever mode the target already had so a
        # rewrite cannot quietly widen or narrow access to it. With no
        # target yet, 0600 is the right answer anyway — everything written
        # through here is document or audit data, and the configured umask
        # default is no wider.
        if path.exists():
            os.chmod(tmp, path.stat().st_mode & 0o7777)
        os.replace(tmp, path)
    except BaseException:
        tmp.unlink(missing_ok=True)
        raise
    # The rename itself has to reach the disk, or a crash can leave the
    # directory entry still pointing at the old file.
    dir_fd = os.open(str(path.parent), os.O_RDONLY)
    try:
        os.fsync(dir_fd)
    finally:
        os.close(dir_fd)


class FileAlreadyExists(FileExistsError):
    """`atomic_write(..., exclusive=True)` found the target name taken."""


@contextmanager
def atomic_write(path: Path, *, exclusive: bool = False) -> Iterator[Path]:
    """Yield a temp path to write to; on clean exit it becomes `path`.

    For writers that hand a filename to a library rather than bytes to a
    file object — Parquet, chiefly. The consequence of a half-written
    Parquet file is worse than losing that one row: DuckDB reads these
    stores through a `dt=*/*.parquet` glob, and a single file with no
    footer fails the whole query. One `kill -9` or one full disk during a
    commit therefore takes down every search, the jobs list, and reprocess
    for every job, until an operator finds the file and deletes it.

    `exclusive=True` additionally refuses to replace an existing target,
    for the append-only assessment history, where clobbering a row
    another writer just created would lose an assessment the audit trail
    already recorded. It uses `os.link`, which fails if the name is taken
    and is atomic — doing this with O_EXCL on the real path instead would
    claim the name *before* the content existed, which is how you end up
    with a zero-byte Parquet file after a crash.
    """
    path = Path(path)
    fd, tmp_name = tempfile.mkstemp(dir=str(path.parent), prefix=path.name, suffix=".tmp")
    os.close(fd)
    tmp = Path(tmp_name)
    try:
        yield tmp
        # The data has to be on the disk before the name points at it;
        # otherwise a crash can leave a correctly-named empty file, which
        # is exactly the unreadable case this exists to prevent.
        with open(tmp, "rb") as f:
            os.fsync(f.fileno())
        if path.exists():
            os.chmod(tmp, path.stat().st_mode & 0o7777)
        if exclusive:
            try:
                os.link(tmp, path)
            except FileExistsError:
                raise FileAlreadyExists(str(path)) from None
        else:
            os.replace(tmp, path)
    except BaseException:
        tmp.unlink(missing_ok=True)
        raise
    finally:
        if exclusive:
            tmp.unlink(missing_ok=True)
    dir_fd = os.open(str(path.parent), os.O_RDONLY)
    try:
        os.fsync(dir_fd)
    finally:
        os.close(dir_fd)


def copy_durably(source: Path, destination: Path) -> None:
    """Publish a complete, fsync'd document before its source can be removed."""
    import shutil

    destination.parent.mkdir(parents=True, exist_ok=True)
    with atomic_write(destination) as tmp:
        shutil.copyfile(source, tmp)


def write_bytes_durably(destination: Path, content: bytes) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    with atomic_write(destination) as tmp:
        tmp.write_bytes(content)


def move_durably(source: Path, destination: Path) -> None:
    if source.resolve() == destination.resolve():
        return
    copy_durably(source, destination)
    source.unlink()
    directory = os.open(str(source.parent), os.O_RDONLY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)
