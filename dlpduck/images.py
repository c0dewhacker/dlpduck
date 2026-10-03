"""Scanner image formats (TIFF, JPEG, PNG) are converted to PDF at claim.

Everything downstream of claim — staging, extraction, the archive, the
console's viewer, reprocessing in extract mode, reindexing — is built
around one PDF per job. Converting once, at the door, keeps all of that
unchanged instead of teaching every one of those paths a second format.

The conversion is deterministic: the same image bytes always produce the
same PDF bytes, and so the same content-derived job id. That is what
makes a re-dropped scan resolve as a duplicate, and what lets crash
recovery re-derive a staged job's id from the staged document. So the
PDF is written here directly rather than through a library that stamps
creation dates or random file identifiers into it.

It is also lossless. A baseline JPEG is embedded byte for byte (PDF
renders DCT data natively); every other frame is decoded and stored
Flate-compressed, which keeps every pixel the scanner produced.

What the original was — its format and its own SHA-256 — is recorded
alongside the job, since the archived PDF is not byte-identical to it.

Decoding an image is parsing untrusted input from the drop folder, so
callers run this in the isolated worker (see dlpduck.extract_worker)
rather than in the daemon. The pixel and page caps below are checked from
each frame's header before any pixel data is decoded.
"""

from __future__ import annotations

import io
import zlib
from dataclasses import dataclass

from dlpduck.types import DocumentTooLarge

# Formats sniffed from content, not trusted from a filename.
_MAGIC: tuple[tuple[bytes, str], ...] = (
    (b"%PDF-", "pdf"),
    (b"II*\x00", "tiff"),
    (b"MM\x00*", "tiff"),
    (b"II+\x00", "tiff"),  # BigTIFF
    (b"MM\x00+", "tiff"),
    (b"\xff\xd8\xff", "jpeg"),
    (b"\x89PNG\r\n\x1a\n", "png"),
)
IMAGE_FORMATS = frozenset({"tiff", "jpeg", "png"})

# Most scanners record a resolution; one that doesn't is far more likely
# to be a 300 dpi office scan than anything else. It only decides the
# page's physical size, never which pixels are kept.
DEFAULT_DPI = 300.0


class UnreadableImage(Exception):
    """A file presented as a scanner image that cannot be decoded. Refused
    at claim, the same as a symlink or an oversized file — there is no PDF
    to stage, so there is nothing for extraction to fail closed on."""


def sniff(data: bytes) -> str | None:
    """The document format from its leading bytes, or None if unknown.

    PDFs are allowed a little leading junk, as readers allow it."""
    for magic, kind in _MAGIC:
        if data.startswith(magic):
            return kind
    if b"%PDF-" in data[:1024]:
        return "pdf"
    return None


@dataclass(frozen=True)
class _Frame:
    width: int
    height: int
    dpi_x: float
    dpi_y: float
    colorspace: str  # DeviceGray | DeviceRGB
    bits: int
    filter: str  # DCTDecode | FlateDecode
    data: bytes


def _dpi(info: dict) -> tuple[float, float]:
    raw = info.get("dpi")
    try:
        x, y = float(raw[0]), float(raw[1])  # type: ignore[index]
    except (TypeError, ValueError, IndexError):
        return DEFAULT_DPI, DEFAULT_DPI
    # A zero or absurd resolution would produce a page metres across or
    # a fraction of a point wide.
    if not (36 <= x <= 2400 and 36 <= y <= 2400):
        return DEFAULT_DPI, DEFAULT_DPI
    return x, y


def _frames(data: bytes, *, max_pages: int, max_pixels: int) -> list[_Frame]:
    from PIL import Image, ImageOps, ImageSequence, UnidentifiedImageError

    try:
        image = Image.open(io.BytesIO(data))
    except (UnidentifiedImageError, OSError, ValueError) as exc:
        raise UnreadableImage(f"not a readable image: {exc}") from None

    with image:
        count = getattr(image, "n_frames", 1)
        if count > max_pages:
            raise DocumentTooLarge(
                f"image has {count} frames, over the configured {max_pages}-page limit"
            )
        frames: list[_Frame] = []
        try:
            for frame in ImageSequence.Iterator(image):
                width, height = frame.size
                # The header is all that has been read so far. Checked
                # before decoding, because decoding is the allocation.
                if width * height > max_pixels:
                    raise DocumentTooLarge(
                        f"image frame is {width}x{height} pixels, over the configured "
                        f"{max_pixels}-pixel limit"
                    )
                dpi_x, dpi_y = _dpi(frame.info)
                orientation = frame.getexif().get(0x0112, 1)
                if (
                    image.format == "JPEG"
                    and count == 1
                    and orientation == 1
                    and frame.mode in ("L", "RGB")
                    and not frame.info.get("progression")
                ):
                    frames.append(
                        _Frame(width, height, dpi_x, dpi_y,
                               "DeviceGray" if frame.mode == "L" else "DeviceRGB",
                               8, "DCTDecode", data)
                    )
                    continue
                decoded = ImageOps.exif_transpose(frame)
                if decoded.mode == "1":
                    # Bilevel (fax/G4) scans stay one bit per pixel: the
                    # same pixels, and an eighth of the size of widening
                    # them to grey. PIL packs 1=white, as DeviceGray reads it.
                    frames.append(
                        _Frame(decoded.width, decoded.height, dpi_x, dpi_y, "DeviceGray", 1,
                               "FlateDecode", zlib.compress(decoded.tobytes(), 6))
                    )
                    continue
                if decoded.mode == "I" or decoded.mode.startswith("I;16"):
                    # 16-bit grey: a plain convert("L") clips rather than
                    # scales, turning anything above 255 solid white.
                    decoded = decoded.convert("I").point(lambda v: v / 256).convert("L")
                if decoded.mode in ("1", "L", "LA", "I", "I;16", "F", "P") and _is_gray(decoded):
                    decoded = decoded.convert("L")
                    space = "DeviceGray"
                else:
                    decoded = decoded.convert("RGB")
                    space = "DeviceRGB"
                frames.append(
                    _Frame(decoded.width, decoded.height, dpi_x, dpi_y, space, 8,
                           "FlateDecode", zlib.compress(decoded.tobytes(), 6))
                )
        except DocumentTooLarge:
            raise
        except (OSError, ValueError, SyntaxError, Image.DecompressionBombError) as exc:
            raise UnreadableImage(f"image could not be decoded: {exc}") from None
    if not frames:
        raise UnreadableImage("image contains no frames")
    return frames


def _is_gray(image) -> bool:
    if image.mode != "P":
        return True
    palette = image.getpalette() or []
    triples = zip(palette[0::3], palette[1::3], palette[2::3], strict=False)
    return all(r == g == b for r, g, b in triples)


def _pdf(frames: list[_Frame]) -> bytes:
    """A minimal, deterministic PDF: one page per frame, each page exactly
    the image at its recorded resolution. No Info dictionary, no /ID, no
    timestamps — nothing that varies between two conversions of one file."""
    objects: list[bytes] = []

    def add(body: bytes) -> int:
        objects.append(body)
        return len(objects)

    catalog = add(b"")  # filled in once the page tree exists
    pages = add(b"")
    kids: list[int] = []
    for frame in frames:
        width_pt = frame.width / frame.dpi_x * 72
        height_pt = frame.height / frame.dpi_y * 72
        image = add(
            b"<< /Type /XObject /Subtype /Image /Width %d /Height %d "
            b"/ColorSpace /%s /BitsPerComponent %d /Filter /%s /Length %d >>\nstream\n"
            % (frame.width, frame.height, frame.colorspace.encode(), frame.bits,
               frame.filter.encode(), len(frame.data))
            + frame.data
            + b"\nendstream"
        )
        content = b"q %.4f 0 0 %.4f 0 0 cm /Im0 Do Q" % (width_pt, height_pt)
        stream = add(b"<< /Length %d >>\nstream\n" % len(content) + content + b"\nendstream")
        kids.append(
            add(
                b"<< /Type /Page /Parent %d 0 R /MediaBox [0 0 %.4f %.4f] "
                b"/Resources << /XObject << /Im0 %d 0 R >> >> /Contents %d 0 R >>"
                % (pages, width_pt, height_pt, image, stream)
            )
        )
    objects[catalog - 1] = b"<< /Type /Catalog /Pages %d 0 R >>" % pages
    objects[pages - 1] = b"<< /Type /Pages /Kids [%s] /Count %d >>" % (
        b" ".join(b"%d 0 R" % k for k in kids),
        len(kids),
    )

    out = io.BytesIO()
    out.write(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
    offsets = []
    for number, body in enumerate(objects, start=1):
        offsets.append(out.tell())
        out.write(b"%d 0 obj\n" % number + body + b"\nendobj\n")
    xref = out.tell()
    out.write(b"xref\n0 %d\n0000000000 65535 f \n" % (len(objects) + 1))
    for offset in offsets:
        out.write(b"%010d 00000 n \n" % offset)
    out.write(
        b"trailer\n<< /Size %d /Root %d 0 R >>\nstartxref\n%d\n%%%%EOF\n"
        % (len(objects) + 1, catalog, xref)
    )
    return out.getvalue()


def image_to_pdf(data: bytes, *, max_pages: int, max_pixels: int) -> bytes:
    """Convert a TIFF/JPEG/PNG scan to a PDF with one page per frame.

    Raises UnreadableImage for anything that will not decode, and
    DocumentTooLarge for more frames than `max_pages` or a frame larger
    than `max_pixels` — both before decoding any pixel data."""
    kind = sniff(data)
    if kind not in IMAGE_FORMATS:
        raise UnreadableImage("not a TIFF, JPEG or PNG image")
    return _pdf(_frames(data, max_pages=max_pages, max_pixels=max_pixels))
