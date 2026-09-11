"""Disposable extraction process: a stuck parser/OCR cannot stall ingestion forever."""
from __future__ import annotations

import json
import logging
import subprocess
import sys
import tempfile
from dataclasses import asdict
from pathlib import Path

from dlpduck.types import DocumentText, EncryptedDocument, TextLine

logger = logging.getLogger("dlpduck.extract_worker")


def extract_isolated(pdf_bytes: bytes, dpi: int, min_chars: int, timeout: float) -> DocumentText:
    with tempfile.TemporaryDirectory(prefix="dlpduck-extract-") as directory:
        result_path = Path(directory) / "result.json"
        try:
            result = subprocess.run(  # noqa: S603 — fixed Python module, no shell
                [sys.executable, "-m", "dlpduck.extract_worker", str(result_path), str(dpi), str(min_chars)],
                input=pdf_bytes, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
                timeout=timeout, check=False,
            )
        except subprocess.TimeoutExpired:
            raise TimeoutError(f"extraction exceeded {timeout:g} seconds") from None
        # The worker configures its own logging (see main()) and writes it
        # to its own stderr, which subprocess.run captured above rather
        # than let inherit straight through — so without this, everything
        # the worker logged (including its own traceback on a crash) was
        # silently discarded the moment the pipe closed, worker after
        # worker, regardless of DLPDUCK_LOG_LEVEL.
        if result.stderr:
            level = logging.DEBUG if result.returncode == 0 else logging.WARNING
            logger.log(level, "extraction worker output:\n%s", result.stderr.decode(errors="replace"))
        if result.returncode == 3:
            raise EncryptedDocument()
        if result.returncode or not result_path.is_file():
            raise RuntimeError("extraction worker failed; document requires inspection")
        raw = json.loads(result_path.read_text())
        return DocumentText(**{**raw, "lines": [TextLine(**line) for line in raw["lines"]]})


def main():
    from dlpduck.extract import LineExtractor
    from dlpduck.tracing import configure_logging

    configure_logging()
    extractor = LineExtractor(dpi=int(sys.argv[2]))
    extractor.NATIVE_MIN_CHARS = int(sys.argv[3])
    try:
        doc = extractor.extract(sys.stdin.buffer.read())
    except EncryptedDocument:
        sys.exit(3)
    Path(sys.argv[1]).write_text(json.dumps(asdict(doc)))


if __name__ == "__main__":
    main()
