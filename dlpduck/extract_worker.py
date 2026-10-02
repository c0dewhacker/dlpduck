"""Disposable worker process for everything that parses an untrusted file.

A stuck parser or OCR model cannot stall ingestion forever, and a crash
inside one — a segfault in PDFium, an allocation a hostile file asked for
— takes down a throwaway child rather than the daemon. That only holds if
*every* parse of drop-folder content happens here: extraction did, but
the claim-time read of a PDF's Info dictionary, the page-count limit, and
image decoding all used to run inside the daemon itself.

Tasks, chosen by the first argument:

- `extract`: full line extraction (dlpduck.extract.LineExtractor).
- `inspect`: a PDF's Info-dictionary metadata, read at claim.
- `convert`: a TIFF/JPEG/PNG scan to PDF (dlpduck.images).

The child caps its own address space (RLIMIT_AS) before importing any
parser, when a limit is configured. It sets it on itself rather than via
`preexec_fn`, which is unsafe in a multi-threaded parent — and the daemon
runs a heartbeat thread, a leader-election thread and an extraction
sweep alongside the watcher.
"""

from __future__ import annotations

import json
import logging
import subprocess
import sys
import tempfile
from dataclasses import asdict
from pathlib import Path
from typing import Any

from dlpduck.types import DocumentText, DocumentTooLarge, EncryptedDocument, TextLine, TooManyPages

logger = logging.getLogger("dlpduck.extract_worker")

# Exit codes the parent understands. Anything else is an unexplained failure.
EXIT_ENCRYPTED = 3
EXIT_TOO_MANY_PAGES = 4
EXIT_UNREADABLE = 5
EXIT_TOO_LARGE = 6


class WorkerFailed(RuntimeError):
    """The worker exited without a result the parent can use."""


def run_isolated(
    task: str,
    payload: bytes,
    args: dict[str, Any],
    *,
    timeout: float,
    memory_mb: int | None = None,
) -> Any:
    """Run one task in a fresh interpreter and return its JSON result.

    Raises TimeoutError, or the typed exception the task raised in the
    child (EncryptedDocument, TooManyPages, UnreadableImage,
    DocumentTooLarge), or WorkerFailed for anything else.
    """
    with tempfile.TemporaryDirectory(prefix="dlpduck-worker-") as directory:
        result_path = Path(directory) / "result.json"
        spec = json.dumps({"task": task, "result": str(result_path), "args": args,
                           "memory_mb": memory_mb})
        try:
            result = subprocess.run(  # noqa: S603 — fixed Python module, no shell
                [sys.executable, "-m", "dlpduck.extract_worker", spec],
                input=payload, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
                timeout=timeout, check=False,
            )
        except subprocess.TimeoutExpired:
            raise TimeoutError(f"{task} exceeded {timeout:g} seconds") from None
        # The worker logs to its own stderr, captured above rather than
        # inherited — so without this everything it logged (including its
        # own traceback on a crash) was discarded the moment the pipe closed.
        if result.stderr:
            level = logging.DEBUG if result.returncode == 0 else logging.WARNING
            logger.log(level, "%s worker output:\n%s", task, result.stderr.decode(errors="replace"))
        detail = _read_json(result_path)
        if result.returncode == EXIT_ENCRYPTED:
            raise EncryptedDocument()
        if result.returncode == EXIT_TOO_MANY_PAGES:
            raise TooManyPages(int((detail or {}).get("page_count", 0)))
        if result.returncode == EXIT_UNREADABLE:
            from dlpduck.images import UnreadableImage

            raise UnreadableImage((detail or {}).get("error", "unreadable image"))
        if result.returncode == EXIT_TOO_LARGE:
            raise DocumentTooLarge((detail or {}).get("error", "document too large"))
        if result.returncode or detail is None:
            raise WorkerFailed(f"{task} worker failed; document requires inspection")
        return detail["result"]


def _read_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text())
    except (OSError, ValueError):
        return None


def extract_isolated(
    pdf_bytes: bytes,
    dpi: int,
    min_chars: int,
    timeout: float,
    *,
    max_pages: int | None = None,
    memory_mb: int | None = None,
    blank_max_ink: float | None = None,
) -> DocumentText:
    try:
        raw = run_isolated(
            "extract", pdf_bytes,
            {"dpi": dpi, "min_chars": min_chars, "max_pages": max_pages,
             "blank_max_ink": blank_max_ink},
            timeout=timeout, memory_mb=memory_mb,
        )
    except TimeoutError:
        raise TimeoutError(f"extraction exceeded {timeout:g} seconds") from None
    except WorkerFailed:
        raise RuntimeError("extraction worker failed; document requires inspection") from None
    return DocumentText(**{**raw, "lines": [TextLine(**line) for line in raw["lines"]]})


def inspect_isolated(pdf_bytes: bytes, *, timeout: float, memory_mb: int | None = None) -> dict:
    """A PDF's Info-dictionary metadata, read in the worker. An unreadable
    PDF yields {} here exactly as it does in-process — extraction proper
    fails it closed later — and so does a worker that dies or hangs."""
    try:
        return run_isolated("inspect", pdf_bytes, {}, timeout=timeout, memory_mb=memory_mb)
    except (TimeoutError, WorkerFailed, EncryptedDocument):
        logger.warning("could not read PDF metadata in the isolated worker; continuing without it")
        return {}


def convert_isolated(
    image_bytes: bytes,
    *,
    max_pages: int,
    max_pixels: int,
    timeout: float,
    memory_mb: int | None = None,
) -> bytes:
    try:
        encoded = run_isolated(
            "convert", image_bytes, {"max_pages": max_pages, "max_pixels": max_pixels},
            timeout=timeout, memory_mb=memory_mb,
        )
    except (TimeoutError, WorkerFailed) as exc:
        from dlpduck.images import UnreadableImage

        raise UnreadableImage(f"image conversion failed: {exc}") from None
    import base64

    return base64.b64decode(encoded)


def _limit_memory(memory_mb: int | None) -> None:
    if not memory_mb:
        return
    import resource

    limit = memory_mb * 1024 * 1024
    resource.setrlimit(resource.RLIMIT_AS, (limit, limit))


def main() -> None:
    from dlpduck.tracing import configure_logging

    spec = json.loads(sys.argv[1])
    _limit_memory(spec.get("memory_mb"))
    configure_logging()
    result_path = Path(spec["result"])
    args = spec["args"]
    payload = sys.stdin.buffer.read()

    def done(value: Any, code: int = 0) -> None:
        result_path.write_text(json.dumps(value))
        sys.exit(code)

    task = spec["task"]
    if task == "extract":
        from dlpduck.extract import LineExtractor

        extractor = LineExtractor(
            dpi=int(args["dpi"]),
            max_pages=args.get("max_pages"),
            blank_max_ink=args.get("blank_max_ink"),
        )
        extractor.NATIVE_MIN_CHARS = int(args["min_chars"])
        try:
            doc = extractor.extract(payload)
        except EncryptedDocument:
            sys.exit(EXIT_ENCRYPTED)
        except TooManyPages as exc:
            done({"page_count": exc.page_count}, EXIT_TOO_MANY_PAGES)
        done({"result": asdict(doc)})
    elif task == "inspect":
        from dlpduck.pdf_metadata import extract_pdf_metadata

        done({"result": extract_pdf_metadata(payload)})
    elif task == "convert":
        import base64

        from dlpduck.images import UnreadableImage, image_to_pdf

        try:
            pdf = image_to_pdf(
                payload, max_pages=int(args["max_pages"]), max_pixels=int(args["max_pixels"])
            )
        except UnreadableImage as exc:
            done({"error": str(exc)}, EXIT_UNREADABLE)
        except DocumentTooLarge as exc:
            done({"error": str(exc)}, EXIT_TOO_LARGE)
        except MemoryError:
            done({"error": "image needs more memory than the worker is allowed"}, EXIT_TOO_LARGE)
        done({"result": base64.b64encode(pdf).decode("ascii")})
    else:
        raise SystemExit(f"unknown worker task {task!r}")


if __name__ == "__main__":
    main()
