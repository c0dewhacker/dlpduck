from __future__ import annotations

from bisect import bisect_right
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from functools import cached_property
from pathlib import Path
from typing import Any


class Severity(str, Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

    @property
    def rank(self) -> int:
        return _RANK[self]


_RANK = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}

# quarantine > flag > ignore
_ACTION_RANK = {"ignore": 0, "flag": 1, "quarantine": 2}


def strongest_action(actions: list[str]) -> str:
    if not actions:
        return "ignore"
    return max(actions, key=lambda a: _ACTION_RANK[a])


@dataclass(frozen=True)
class TextLine:
    line_number: int  # 0-indexed, document-global
    page_number: int  # 1-indexed
    line_on_page: int  # 0-indexed within the page
    lines_on_page: int  # total lines on this page, lets a rule address the footer
    text: str
    source: str  # "native" | "ocr"
    confidence: float | None = None  # OCR mean, None if native


@dataclass(frozen=True)
class DLPHit:
    rule_id: str
    rule_name: str
    severity: Severity
    action: str  # quarantine | flag | ignore
    page_number: int
    line_number: int
    line_on_page: int
    start: int  # char offset within the line/document text used for matching
    end: int
    masked_text: str  # never the raw value
    match_hmac: str  # keyed digest for correlation
    validator: str | None = None


@dataclass
class DocumentText:
    lines: list[TextLine] = field(default_factory=list)
    page_count: int = 0
    ocr_page_count: int = 0
    degraded: bool = False  # any page failed extraction -> fail closed
    failed_page_count: int = 0  # pages that raised, distinct from valid empty OCR

    def add_line(self, line: TextLine) -> None:
        self.lines.append(line)
        # cached_property values below are invalidated by callers rebuilding
        # DocumentText rather than mutating a fully-built one mid-flight.

    @cached_property
    def full_text(self) -> str:
        return "\n".join(line.text for line in self.lines)

    @cached_property
    def _offsets(self) -> list[int]:
        out: list[int] = []
        n = 0
        for line in self.lines:
            out.append(n)
            n += len(line.text) + 1  # +1 for the joining "\n"
        return out

    def line_at(self, offset: int) -> TextLine:
        if not self.lines:
            raise IndexError("line_at called on a document with no lines")
        idx = bisect_right(self._offsets, offset) - 1
        idx = max(0, min(idx, len(self.lines) - 1))
        return self.lines[idx]

    def offset_of(self, line_number: int) -> int:
        """Where this line begins within `full_text`. A DLPHit's start/end
        are stored relative to its own line, so re-deriving the matched
        value later means slicing `full_text` from here — which also lets a
        value that wrapped across a line break be recovered whole.
        """
        if not 0 <= line_number < len(self._offsets):
            raise IndexError(f"no line {line_number} in this document")
        return self._offsets[line_number]

    @property
    def min_ocr_confidence(self) -> float | None:
        confidences = [line.confidence for line in self.lines if line.confidence is not None]
        return min(confidences) if confidences else None


@dataclass
class JobContext:
    # blake2b(pdf_bytes, digest_size=16).hexdigest() — 32 hex chars, no
    # truncation. dlpduck.content.validate_job_id enforces that shape
    # before any job id reaches a filesystem glob.
    job_id: str
    received_at: datetime
    source_name: str
    staging_dir: Path
    pdf_path: Path
    pdf_sha256: str
    metadata: dict[str, Any]
    text: DocumentText | None = None  # set once extraction completes
    hits: list[DLPHit] = field(default_factory=list)
    disposition: str = "pending"  # pending | archive | quarantine | failed
    reason: str | None = None
    audit_fields: dict[str, Any] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)

    @property
    def highest_severity(self) -> Severity | None:
        if not self.hits:
            return None
        return max((h.severity for h in self.hits), key=lambda s: s.rank)

    @property
    def flagged(self) -> bool:
        return bool(self.hits)


class EncryptedDocument(Exception):
    """Raised when a PDF requires a password to open."""


class DocumentTooLarge(Exception):
    """Raised at claim time when limits.max_bytes or limits.max_pages is exceeded."""


class PageTooLarge(Exception):
    """Raised when a page's declared size means it cannot be rasterised
    within the extractor's pixel cap at any usable resolution. Handled as
    a per-page extraction failure, so the document is marked degraded and
    quarantined rather than allocating the bitmap the PDF asked for."""


class UnsafeSourceFile(Exception):
    """Raised at claim time for a source file this daemon refuses to open —
    currently a symlink, which would otherwise be followed out of the drop
    folder into whatever it points at."""


class RuleBudgetExceeded(Exception):
    """Raised when a single rule exceeds its per-document time budget."""

    def __init__(self, rule_id: str):
        super().__init__(f"rule {rule_id!r} exceeded its time budget")
        self.rule_id = rule_id
