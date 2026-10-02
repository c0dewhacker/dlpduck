"""Scanner image intake: TIFF/JPEG/PNG converted to PDF at claim, and drop
folder matching that ignores the case of a suffix."""

import io
import json
from pathlib import Path

import pypdfium2 as pdfium
import pytest
from PIL import Image, ImageChops, ImageDraw

from dlpduck.config import Config
from dlpduck.extract_worker import convert_isolated, inspect_isolated
from dlpduck.images import UnreadableImage, image_to_pdf, sniff
from dlpduck.pipeline import Pipeline, content_job_id
from dlpduck.types import DocumentTooLarge
from dlpduck.watcher import Watcher
from tests.pdf_factory import image_only_pdf, make_pdf, with_metadata

DEFAULT_RULES_PATH = Path(__file__).resolve().parents[1] / "dlpduck" / "builtin_rules" / "default.yaml"


def _page(text: str = "page", mode: str = "L", size=(600, 200)) -> Image.Image:
    white = 1 if mode == "1" else (255 if mode == "L" else (255, 255, 255))
    black = 0 if mode in ("1", "L") else (0, 0, 0)
    image = Image.new(mode, size, white)
    ImageDraw.Draw(image).text((20, 80), text, fill=black)
    return image


def _encode(image: Image.Image, fmt: str, **kwargs) -> bytes:
    out = io.BytesIO()
    image.save(out, fmt, **kwargs)
    return out.getvalue()


def _scanned_tiff(lines: list[str]) -> bytes:
    """A real scan's pixels: an image-only page rasterised and saved as
    the TIFF an MFP would have written."""
    with pdfium.PdfDocument(image_only_pdf(lines)) as document:
        image = document[0].render(scale=200 / 72).to_pil().convert("L")
    return _encode(image, "TIFF", dpi=(200, 200), compression="tiff_lzw")


def _config(tmp_path, **source):
    src = tmp_path / "drops"
    src.mkdir(exist_ok=True)
    return Config.model_validate(
        {
            "source": {"name": "t", "path": str(src), "metadata_format": "none", **source},
            "destination": {
                "archive": str(tmp_path / "archive"),
                "quarantine": str(tmp_path / "quarantine"),
                "work_dir": str(tmp_path / "work"),
            },
            "extraction": {"isolate_worker": False},
            "dlp": {"rules": [{"include": str(DEFAULT_RULES_PATH)}]},
        }
    )


@pytest.fixture(autouse=True)
def _key(monkeypatch):
    monkeypatch.setenv("DLPDUCK_HMAC_KEY", "test-key-not-for-production")


class TestConversion:
    @pytest.mark.parametrize(
        ("fmt", "kind", "kwargs"),
        [("TIFF", "tiff", {"compression": "tiff_lzw"}), ("JPEG", "jpeg", {}), ("PNG", "png", {})],
    )
    def test_each_format_converts_to_a_one_page_pdf(self, fmt, kind, kwargs):
        mode = "RGB" if fmt == "JPEG" else "L"
        data = _encode(_page(mode=mode), fmt, **kwargs)
        assert sniff(data) == kind

        pdf = image_to_pdf(data, max_pages=10, max_pixels=10**8)

        with pdfium.PdfDocument(pdf) as document:
            assert len(document) == 1

    def test_conversion_is_deterministic(self):
        """The job id is derived from the converted bytes, so a re-dropped
        scan is only recognised as a duplicate if this holds."""
        data = _encode(_page(), "TIFF", compression="tiff_lzw")
        assert image_to_pdf(data, max_pages=1, max_pixels=10**8) == image_to_pdf(
            data, max_pages=1, max_pixels=10**8
        )

    def test_a_multi_page_tiff_becomes_one_page_per_frame(self):
        frames = [_page("one"), _page("two"), _page("three")]
        data = _encode(frames[0], "TIFF", save_all=True, append_images=frames[1:])

        pdf = image_to_pdf(data, max_pages=10, max_pixels=10**8)

        with pdfium.PdfDocument(pdf) as document:
            assert len(document) == 3

    def test_page_size_follows_the_recorded_resolution(self):
        data = _encode(_page(size=(600, 300)), "PNG", dpi=(150, 150))
        pdf = image_to_pdf(data, max_pages=1, max_pixels=10**8)
        with pdfium.PdfDocument(pdf) as document:
            assert document[0].get_size() == pytest.approx((288.0, 144.0), abs=0.5)

    def test_a_baseline_jpeg_is_embedded_byte_for_byte(self):
        data = _encode(_page(mode="RGB"), "JPEG")
        assert data in image_to_pdf(data, max_pages=1, max_pixels=10**8)

    def test_pixels_survive_the_round_trip(self):
        image = _page("lossless", mode="1")
        pdf = image_to_pdf(_encode(image, "TIFF", compression="group4"), max_pages=1,
                           max_pixels=10**8)
        with pdfium.PdfDocument(pdf) as document:
            rendered = document[0].render(scale=300 / 72).to_pil().convert("L")
        assert rendered.size == image.size
        assert ImageChops.difference(rendered, image.convert("L")).getbbox() is None

    def test_too_many_frames_is_refused_before_decoding(self):
        frames = [_page(str(i)) for i in range(4)]
        data = _encode(frames[0], "TIFF", save_all=True, append_images=frames[1:])
        with pytest.raises(DocumentTooLarge, match="4 frames"):
            image_to_pdf(data, max_pages=3, max_pixels=10**8)

    def test_an_oversized_frame_is_refused_before_decoding(self):
        data = _encode(_page(size=(1000, 1000)), "PNG")
        with pytest.raises(DocumentTooLarge, match="pixel limit"):
            image_to_pdf(data, max_pages=1, max_pixels=999_999)

    def test_garbage_is_unreadable(self):
        with pytest.raises(UnreadableImage):
            image_to_pdf(b"II*\x00" + b"\x00" * 64, max_pages=1, max_pixels=10**8)
        with pytest.raises(UnreadableImage):
            image_to_pdf(b"not an image", max_pages=1, max_pixels=10**8)


class TestTheIsolatedWorker:
    def test_conversion_runs_in_the_worker(self):
        data = _encode(_page(), "PNG")
        assert convert_isolated(data, max_pages=1, max_pixels=10**8, timeout=60) == image_to_pdf(
            data, max_pages=1, max_pixels=10**8
        )

    def test_typed_refusals_cross_the_process_boundary(self):
        with pytest.raises(DocumentTooLarge):
            convert_isolated(_encode(_page(size=(1000, 1000)), "PNG"), max_pages=1,
                             max_pixels=10, timeout=60)
        with pytest.raises(UnreadableImage):
            convert_isolated(b"II*\x00garbage", max_pages=1, max_pixels=10**8, timeout=60)

    def test_pdf_metadata_is_read_in_the_worker(self):
        pdf = with_metadata(make_pdf([["content"]]), {"Title": "Quarterly"})
        assert inspect_isolated(pdf, timeout=60)["pdf_title"] == "Quarterly"
        assert inspect_isolated(b"not a pdf", timeout=60) == {}


class TestThePipelineTakesScans:
    def test_a_tiff_is_converted_scanned_and_quarantined(self, tmp_path):
        config = _config(tmp_path)
        pipeline = Pipeline(config)
        scan = config.source.path / "SCAN0001.TIF"
        raw = _scanned_tiff(["Card 4111 1111 1111 1111"])
        scan.write_bytes(raw)

        ctx = pipeline.run_job(scan, None, config.destination.work_dir / "_processing")

        assert ctx.disposition == "quarantine"
        assert any(h.rule_id == "pan.generic" for h in ctx.hits)
        archived = next(config.destination.quarantine.glob("dt=*/*.pdf"))
        assert archived.read_bytes()[:5] == b"%PDF-"
        [converted] = [
            e for e in pipeline.audit.events_for_job(ctx.job_id) if e["event"] == "document.converted"
        ]
        assert converted["source_format"] == "tiff"
        assert converted["filename"] == "SCAN0001.TIF"
        import hashlib

        assert converted["source_sha256"] == hashlib.sha256(raw).hexdigest()

    def test_the_same_scan_dropped_twice_is_a_duplicate(self, tmp_path):
        config = _config(tmp_path)
        pipeline = Pipeline(config)
        staging = config.destination.work_dir / "_processing"
        data = _encode(_page("ordinary"), "PNG")
        (config.source.path / "a.png").write_bytes(data)
        first = pipeline.run_job(config.source.path / "a.png", None, staging)
        (config.source.path / "b.png").write_bytes(data)

        second = pipeline.run_job(config.source.path / "b.png", None, staging)

        assert second.job_id == first.job_id
        assert second.reason == "duplicate_receipt"

    def test_an_unreadable_image_is_refused_at_claim(self, tmp_path):
        config = _config(tmp_path)
        pipeline = Pipeline(config)
        bad = config.source.path / "broken.tif"
        bad.write_bytes(b"II*\x00" + b"\xff" * 32)

        with pytest.raises(UnreadableImage):
            pipeline.run_job(bad, None, config.destination.work_dir / "_processing")

        assert not bad.exists()
        [folder] = (config.destination.work_dir / "failed").iterdir()
        assert json.loads((folder / "metadata.json").read_text())["reason"] == "UnreadableImage"

    def test_a_staged_conversion_survives_crash_recovery(self, tmp_path):
        """Recovery re-derives the job id from the staged document, which
        must therefore be the converted PDF and not the original image."""
        config = _config(tmp_path)
        pipeline = Pipeline(config)
        staging = config.destination.work_dir / "_processing"
        scan = config.source.path / "scan.jpg"
        scan.write_bytes(_encode(_page(mode="RGB"), "JPEG"))

        staged = pipeline.stage(scan, None, staging)
        manifest = json.loads((staging / staged.job_id / "manifest.json").read_text())
        [ctx] = pipeline.resume_staged(staging)

        assert manifest["origin"]["source_format"] == "jpeg"
        assert ctx.job_id == staged.job_id
        archived = next(config.destination.archive.glob("dt=*/*.pdf"))
        assert content_job_id(archived.read_bytes()) == ctx.job_id

    def test_a_failed_conversion_can_be_retried_under_its_original_name(self, tmp_path):
        """A retry restores the stored document as `scan.tif` — but what's
        stored is already the converted PDF, so the format is sniffed
        rather than taken from the name."""
        from dlpduck.failures import FailureQueue

        config = _config(tmp_path, metadata_format="none")
        config.limits.max_pages = 1
        pipeline = Pipeline(config)
        staging = config.destination.work_dir / "_processing"
        frames = [_page("one"), _page("two")]
        scan = config.source.path / "scan.tif"
        scan.write_bytes(_encode(frames[0], "TIFF", save_all=True, append_images=frames[1:]))
        with pytest.raises(DocumentTooLarge):
            pipeline.run_job(scan, None, staging)
        [folder] = (config.destination.work_dir / "failed").iterdir()

        config.limits.max_pages = 5
        FailureQueue(Pipeline(config)).retry("failed", folder.name, "limit raised", "admin")

        assert list(config.destination.archive.glob("dt=*/*.pdf")) or list(
            config.destination.quarantine.glob("dt=*/*.pdf")
        )


class TestTheWatcherIgnoresCase:
    def test_uppercase_suffixes_and_companions_are_picked_up(self, tmp_path):
        config = _config(tmp_path, metadata_format="xml", metadata_suffix=".xml",
                         stability_polls=1, metadata_grace_polls=0)
        watcher = Watcher(config, Pipeline(config))
        (config.source.path / "SCAN0001.PDF").write_bytes(b"%PDF-1.4")
        (config.source.path / "SCAN0001.XML").write_text("<m/>")
        (config.source.path / "photo.JPeG").write_bytes(b"\xff\xd8\xff")
        (config.source.path / "notes.txt").write_text("ignored")

        ready = dict(watcher.discover_ready())

        assert {p.name for p in ready} == {"SCAN0001.PDF", "photo.JPeG"}
        assert ready[config.source.path / "SCAN0001.PDF"].name == "SCAN0001.XML"

    def test_image_intake_can_be_turned_off(self, tmp_path):
        config = _config(tmp_path, image_suffixes=[], stability_polls=1)
        watcher = Watcher(config, Pipeline(config))
        (config.source.path / "scan.tif").write_bytes(b"II*\x00")
        assert watcher.discover_ready() == []
