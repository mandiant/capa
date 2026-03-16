from __future__ import annotations

import contextlib
import fcntl
import hashlib
import logging
import os
import time
from pathlib import Path
from typing import Iterator

import idapro  # must be first: mutates sys.path so ida_auto and ida_domain are importable
import ida_auto
from ida_domain.database import Database, IdaCommandOptions

logger = logging.getLogger(__name__)

DATABASE_ACCESS_TIMEOUT = 5.0
DATABASE_ANALYSIS_TIMEOUT = 120.0
DATABASE_POLL_INTERVAL = 0.25


def get_cache_dir() -> Path:
    xdg = os.environ.get("XDG_CACHE_HOME")
    if xdg:
        base = Path(xdg)
    else:
        base = Path.home() / ".cache"
    return base / "mandiant" / "mapa"


def compute_file_hashes(file_path: Path) -> tuple[str, str]:
    """Compute (md5, sha256) for a file.

    Raises:
        OSError: If the file cannot be read.
    """
    md5_digest = hashlib.md5()
    sha256_digest = hashlib.sha256()
    with file_path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            md5_digest.update(chunk)
            sha256_digest.update(chunk)
    return md5_digest.hexdigest(), sha256_digest.hexdigest()


def _wait_for_repack(db_path: Path, timeout: float) -> None:
    nam_path = db_path.with_suffix(".nam")
    deadline = time.monotonic() + timeout
    while nam_path.exists():
        if time.monotonic() >= deadline:
            raise RuntimeError(
                f"Database {db_path} appears to be open in another program "
                f"({nam_path} still exists after {timeout:.0f}s)."
            )
        time.sleep(DATABASE_POLL_INTERVAL)


@contextlib.contextmanager
def database_access_guard(db_path: Path, timeout: float) -> Iterator[None]:
    """Advisory guard that serialises access to an IDA database.

    Uses .nam polling + flock on <db>.lock with TOCTOU re-check.

    Raises:
        RuntimeError: On timeout waiting for the database.
    """
    _wait_for_repack(db_path, timeout)

    lock_path = Path(str(db_path) + ".lock")
    lock_fd = lock_path.open("w")
    deadline = time.monotonic() + timeout
    try:
        while True:
            try:
                fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except OSError:
                if time.monotonic() >= deadline:
                    raise RuntimeError(
                        f"Timed out waiting for lock on {db_path} after {timeout:.0f}s."
                    )
                time.sleep(DATABASE_POLL_INTERVAL)

        _wait_for_repack(db_path, max(0, deadline - time.monotonic()))
        yield
    finally:
        fcntl.flock(lock_fd, fcntl.LOCK_UN)
        lock_fd.close()


def resolve_database(file_path: Path) -> tuple[Path, str, str]:
    """Resolve an input path to an .i64/.idb database path.

    Returns (db_path, md5, sha256). For existing databases, hashes are empty
    strings (they'll be read from IDA metadata instead).

    Raises:
        RuntimeError: If analysis or caching fails.
    """
    suffix = file_path.suffix.lower()
    if suffix in {".i64", ".idb"}:
        logger.debug("Using existing database: %s", file_path)
        return file_path, "", ""

    cache_dir = get_cache_dir()
    cache_dir.mkdir(parents=True, exist_ok=True)

    md5, sha256 = compute_file_hashes(file_path)
    cache_path = cache_dir / f"{sha256}.i64"

    if cache_path.exists():
        logger.debug("Cache hit for %s -> %s", file_path, cache_path)
        return cache_path, md5, sha256

    logger.debug("Cache miss for %s; analyzing to %s", file_path, cache_path)
    with database_access_guard(cache_path, timeout=DATABASE_ANALYSIS_TIMEOUT):
        if cache_path.exists():
            logger.debug("Cache populated while waiting for lock: %s", cache_path)
            return cache_path, md5, sha256

        logger.info("Analyzing %s (this may take a moment)...", file_path.name)
        idapro.enable_console_messages(False)
        ida_options = IdaCommandOptions(
            auto_analysis=True,
            new_database=True,
            output_database=str(cache_path),
            load_resources=True,
            plugin_options="lumina:host=0.0.0.0 -Osecondary_lumina:host=0.0.0.0",
        )
        try:
            with Database.open(str(file_path), ida_options, save_on_close=True):
                ida_auto.auto_wait()
        except Exception as exc:
            raise RuntimeError(f"Analysis failed for {file_path}: {exc}") from exc

        if not cache_path.exists():
            raise RuntimeError(f"Analysis produced no database for {file_path}")

        logger.debug("Analysis completed: %s", cache_path)
        return cache_path, md5, sha256


@contextlib.contextmanager
def open_database_session(db_path: Path, auto_analysis: bool = False) -> Iterator[Database]:
    """Open a database session with advisory locking.

    Raises:
        RuntimeError: If opening fails or the database is locked.
    """
    with database_access_guard(db_path, timeout=DATABASE_ACCESS_TIMEOUT):
        ida_options = IdaCommandOptions(auto_analysis=auto_analysis, new_database=False)
        logger.debug("Opening database session: %s (auto_analysis=%s)", db_path, auto_analysis)
        idapro.enable_console_messages(False)
        try:
            database = Database.open(str(db_path), ida_options, save_on_close=False)
        except Exception as exc:
            raise RuntimeError(f"Failed to open {db_path}: {exc}") from exc

        with database:
            if auto_analysis:
                ida_auto.auto_wait()
            yield database

        logger.debug("Closed database session: %s", db_path)
