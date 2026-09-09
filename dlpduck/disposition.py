"""One policy for initial assessment and every reassessment."""
from dlpduck.types import DLPHit, DocumentText


def decide(text: DocumentText, hits: list[DLPHit], quarantine_on_degraded: bool) -> tuple[str, str | None]:
    if quarantine_on_degraded:
        if text.failed_page_count:
            return "quarantine", "degraded_extraction"
        if text.page_count > 0 and not text.lines:
            return "quarantine", "no_text_extracted"
        if text.degraded:
            return "quarantine", "degraded_extraction"
    if any(h.action == "quarantine" for h in hits):
        return "quarantine", "dlp_hit"
    return "archive", None
