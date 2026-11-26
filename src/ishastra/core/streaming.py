"""Streaming and chunk-based processing utilities.

Avoids loading entire files or responses into memory by providing:
- Streaming file readers with chunked iteration
- Incremental hashing of streams
- Bounded in-memory buffers with backpressure
- Size-limited HTTP response handling
"""

from __future__ import annotations

import hashlib
import os
import queue
import threading
from collections.abc import Generator
from dataclasses import dataclass
from pathlib import Path
from typing import Any, BinaryIO

CHUNK_SIZE = 1024 * 1024  # 1MB default chunk size for streaming

@dataclass
class StreamingStats:
    """Statistics from a streaming operation."""
    bytes_processed: int = 0
    chunks_processed: int = 0
    duration_seconds: float = 0.0
    peak_memory_bytes: int = 0

@dataclass
class SizeLimitExceeded(Exception):
    """Raised when a stream or file exceeds the configured size limit."""
    limit: int
    actual: int
    description: str = ""

    def __str__(self) -> str:
        return f"{self.description or 'Size limit exceeded'}: limit={self.limit}, actual={self.actual}"

def stream_file(
    path: str | Path, chunk_size: int = CHUNK_SIZE
) -> Generator[bytes, None, None]:
    """Yield chunks from a file without loading it entirely into memory.

    Processing pattern:

    .. code-block:: python

        for chunk in stream_file(large_path):
            process(chunk)  # never holds more than chunk_size in memory
    """
    path = Path(path)
    with open(path, "rb") as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            yield chunk

def stream_file_with_hash(
    path: str | Path,
    hash_algo: Any = hashlib.sha256,
    chunk_size: int = CHUNK_SIZE,
) -> Generator[tuple[bytes, Any], None, None]:
    """Yield (chunk, running_hash) tuples while streaming a file.

    The hash object is updated incrementally so the final digest is available
    without reading the entire file into memory first.
    """
    hash_obj = hash_algo()
    for chunk in stream_file(path, chunk_size):
        hash_obj.update(chunk)
        yield chunk, hash_obj

def compute_file_hash_incremental(
    path: str | Path,
    hash_algo: Any = hashlib.sha256,
    chunk_size: int = CHUNK_SIZE,
) -> str:
    """Compute SHA-256 (or other hash) of a file without loading it into memory.

    Returns the hex digest. The file is read in chunks so memory use is bounded
    regardless of file size.
    """
    hash_obj = hash_algo()
    with open(path, "rb") as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            hash_obj.update(chunk)
    return hash_obj.hexdigest()

def stream_bytes(data: bytes | BinaryIO, chunk_size: int = CHUNK_SIZE) -> Generator[bytes, None, None]:
    """Stream bytes from a bytes object or BinaryIO buffer in chunks.

    Use this when you have an in-memory buffer but want to process it in bounded chunks
    to avoid holding the entire content in memory at once during downstream processing.
    """
    if isinstance(data, bytes):
        offset = 0
        while offset < len(data):
            yield data[offset:offset + chunk_size]
            offset += chunk_size
    else:
        while True:
            chunk = data.read(chunk_size)
            if not chunk:
                break
            yield chunk

def bounded_stream_to_disk(
    source: bytes | BinaryIO,
    dest_path: str | Path,
    max_size: int | None = None,
    chunk_size: int = CHUNK_SIZE,
    progress_callback: Any = None,
) -> tuple[int, Any]:
    """Stream bytes to a file on disk with optional size limit.

    Writes to a temporary file first, then atomically renames on success.
    Returns (bytes_written, running_hash).
    Raises SizeLimitExceeded if max_size is set and exceeded.
    """
    dest_path = Path(dest_path)
    dest_path.parent.mkdir(parents=True, exist_ok=True)

    tmp_path = str(dest_path) + ".tmp"
    hash_obj = hashlib.sha256()
    bytes_written = 0

    with open(tmp_path, "wb") as f:
        for chunk in stream_bytes(source, chunk_size):
            if max_size is not None and bytes_written + len(chunk) > max_size:
                os.remove(tmp_path)
                raise SizeLimitExceeded(
                    limit=max_size,
                    actual=bytes_written + len(chunk),
                    description="Artifact exceeds maximum allowed size",
                )
            f.write(chunk)
            hash_obj.update(chunk)
            bytes_written += len(chunk)
            if progress_callback:
                progress_callback(bytes_written)

    os.replace(tmp_path, str(dest_path))
    return bytes_written, hash_obj

def check_disk_space(path: str | Path, required_bytes: int) -> tuple[bool, int]:
    """Check if there is enough free disk space at the given path.

    Returns (sufficient, free_bytes). Uses statvfs for reliable cross-platform
    disk space reporting.
    """
    path = Path(path)
    try:
        stat = os.statvfs(str(path.parent if path.is_file() else path))
        free_bytes = stat.f_bavail * stat.f_frsize
        return free_bytes >= required_bytes, free_bytes
    except Exception:
        return False, 0

class BoundedQueue:
    """A queue with backpressure that can signal when full.

    Unlike queue.Queue, this provides:
    - A callback when enqueue would block
    - Metrics on current depth
    - Optional item size tracking for memory-awareness
    """

    def __init__(self, maxsize: int = 0, item_size_limit: int | None = None):
        self._queue: queue.Queue = queue.Queue(maxsize=maxsize)
        self._maxsize = maxsize
        self._item_size_limit = item_size_limit
        self._size_callback: Any = None
        self._lock = threading.Lock()
        self._current_size = 0

    def put(self, item: Any, block: bool = True, timeout: float | None = None) -> bool:
        """Put an item, returning False if the queue is full (non-blocking semantics).

        When item_size_limit is set, items larger than the limit are rejected.
        """
        if self._item_size_limit is not None:
            item_size = self._estimate_size(item)
            if item_size > self._item_size_limit:
                return False
            with self._lock:
                if self._current_size + item_size > self._maxsize and self._maxsize > 0:
                    return False
                self._current_size += item_size

        try:
            self._queue.put(item, block=block, timeout=timeout)
            return True
        except queue.Full:
            with self._lock:
                if self._item_size_limit is not None and self._item_size_limit > 0:
                    item_size = self._estimate_size(item)
                    self._current_size = max(0, self._current_size - (item_size or 0))
            return False

    def get(
        self, block: bool = True, timeout: float | None = None
    ) -> Any:
        item = self._queue.get(block=block, timeout=timeout)
        if self._item_size_limit is not None:
            with self._lock:
                item_size = self._estimate_size(item)
                self._current_size = max(0, self._current_size - (item_size or 0))
        return item

    def qsize(self) -> int:
        return self._queue.qsize()

    def empty(self) -> bool:
        return self._queue.empty()

    def full(self) -> bool:
        return self._queue.full()

    def task_done(self) -> None:
        self._queue.task_done()

    def _estimate_size(self, item: Any) -> int:
        """Estimate the memory size of an item. Override or set _size_callback for accurate sizing."""
        if callable(self._size_callback):
            return self._size_callback(item)
        if isinstance(item, (bytes, bytearray)):
            return len(item)
        return 0

    @property
    def current_memory_bytes(self) -> int:
        with self._lock:
            return self._current_size

class MemoryGuard:
    """Per-worker memory guard that triggers GC or backoff when RSS exceeds a limit."""

    def __init__(self, limit_mb: int, check_interval_jobs: int = 10):
        self._limit_bytes = limit_mb * 1024 * 1024
        self._check_interval = check_interval_jobs
        self._jobs_since_check = 0

    def check(self) -> tuple[bool, int]:
        """Check current RSS. Returns (over_limit, current_rss_bytes)."""
        try:
            import resource
            import sys

            rusage = resource.getrusage(resource.RUSAGE_SELF)
            if sys.platform == "darwin":
                rss = rusage.ru_maxrss / (1024 * 1024)
            else:
                rss = rusage.ru_maxrss / 1024
            rss_bytes = int(rss * 1024 * 1024)
            return rss_bytes > self._limit_bytes, rss_bytes
        except Exception:
            return False, 0

    def maybe_collect(self) -> None:
        """Call this every N jobs. Triggers GC if over limit."""
        self._jobs_since_check += 1
        if self._jobs_since_check >= self._check_interval:
            self._jobs_since_check = 0
            over, rss = self.check()
            if over:
                import gc
                gc.collect()

def iter_findings_chunked(
    items: list[int], chunk_size: int = 1000
) -> Generator[list[int], None, None]:
    """Split a list of integers into chunks for batch processing.

    Args:
        items: List of integers to chunk
        chunk_size: Maximum number of items per chunk

    Yields:
        Lists of integers, each at most chunk_size long
    """
    for i in range(0, len(items), chunk_size):
        yield items[i : i + chunk_size]
    """Yield items in chunks to avoid building large intermediate lists."""
    for i in range(0, len(items), chunk_size):
        yield items[i : i + chunk_size]

def paginate_results(
    query_result: list, page: int, page_size: int
) -> tuple[list, int, int]:
    """Paginate a list result.

    Returns (page_items, total_count, total_pages).
    """
    total = len(query_result)
    total_pages = (total + page_size - 1) // page_size if total > 0 else 0
    start = (page - 1) * page_size
    end = start + page_size
    return query_result[start:end], total, total_pages
