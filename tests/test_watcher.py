"""discover_ready() is the fix for MFPs writing non-atomically: a naive
create-event watch reads half-written PDFs, so a candidate must hold a
stable size across N consecutive polls before it's claimed.
"""

from pathlib import Path

import pytest

from dlpduck.config import Config
from dlpduck.pipeline import Pipeline
from dlpduck.watcher import Watcher

DEFAULT_RULES_PATH = Path(__file__).resolve().parents[1] / "dlpduck" / "builtin_rules" / "default.yaml"


@pytest.fixture
def watcher(tmp_path, monkeypatch):
    monkeypatch.setenv("DLPDUCK_HMAC_KEY", "test-key-not-for-production")
    src = tmp_path / "drops"
    src.mkdir()
    config = Config.model_validate(
        {
            "source": {
                "name": "test-source",
                "path": str(src),
                "metadata_format": "none",
                "stability_polls": 2,
            },
            "destination": {
                "archive": str(tmp_path / "archive"),
                "quarantine": str(tmp_path / "quarantine"),
                "work_dir": str(tmp_path / "work"),
            },
            "dlp": {"rules": [{"include": str(DEFAULT_RULES_PATH)}]},
        }
    )
    pipeline = Pipeline(config)
    return Watcher(config, pipeline)


class TestStabilityGate:
    def test_a_growing_file_is_never_ready(self, watcher):
        pdf = watcher.config.source.path / "growing.pdf"
        pdf.write_bytes(b"partial")
        assert watcher.discover_ready() == []

        pdf.write_bytes(b"partial-more-bytes-appended")  # still growing
        assert watcher.discover_ready() == []

    def test_a_file_becomes_ready_once_stable_for_the_configured_poll_count(self, watcher):
        pdf = watcher.config.source.path / "steady.pdf"
        pdf.write_bytes(b"final content, unchanging")

        assert watcher.discover_ready() == []  # poll 1: first sighting
        ready = watcher.discover_ready()  # poll 2: same size again
        assert len(ready) == 1
        assert ready[0][0] == pdf

    def test_ready_file_is_only_returned_once(self, watcher):
        pdf = watcher.config.source.path / "steady.pdf"
        pdf.write_bytes(b"final content")
        watcher.discover_ready()
        watcher.discover_ready()  # becomes ready here
        assert watcher.discover_ready() == []  # already claimed, not re-offered

    def test_a_file_that_grows_after_looking_briefly_stable_resets_the_counter(self, watcher):
        # stability_polls=2 for this fixture: growing between poll 1 and 2
        # must cost the file its progress, so it takes two MORE stable
        # polls after the change, not just one, before it's ready.
        pdf = watcher.config.source.path / "jumpy.pdf"
        pdf.write_bytes(b"stage one")
        assert watcher.discover_ready() == []  # poll 1: first sighting at size A

        pdf.write_bytes(b"stage one, now longer")
        assert watcher.discover_ready() == []  # poll 2: size changed -> counter resets to size B

        ready = watcher.discover_ready()  # poll 3: size B held for a second poll
        assert len(ready) == 1
        assert ready[0][0] == pdf

    def test_companion_is_picked_up_when_it_arrives_within_the_grace_window(self, tmp_path, monkeypatch):
        monkeypatch.setenv("DLPDUCK_HMAC_KEY", "test-key-not-for-production")
        src = tmp_path / "drops"
        src.mkdir()
        config = Config.model_validate(
            {
                "source": {
                    "name": "test-source",
                    "path": str(src),
                    "metadata_format": "xml",
                    "metadata_suffix": ".xml",
                    "stability_polls": 1,
                },
                "destination": {
                    "archive": str(tmp_path / "archive"),
                    "quarantine": str(tmp_path / "quarantine"),
                    "work_dir": str(tmp_path / "work"),
                },
                "dlp": {"rules": [{"include": str(DEFAULT_RULES_PATH)}]},
            }
        )
        w = Watcher(config, Pipeline(config))
        pdf = src / "doc.pdf"
        pdf.write_bytes(b"content")

        assert w.discover_ready() == []  # no companion .xml yet, still within grace

        (src / "doc.xml").write_bytes(b"<meta/>")
        ready = w.discover_ready()
        assert len(ready) == 1
        assert ready[0] == (pdf, src / "doc.xml")

    def test_metadata_is_optional_a_bare_pdf_is_eventually_claimed_without_one(
        self, tmp_path, monkeypatch
    ):
        # The common "someone just drops a PDF, no XML/JSON ever comes"
        # case — a companion is a convenience, never a requirement,
        # even with metadata_format configured.
        monkeypatch.setenv("DLPDUCK_HMAC_KEY", "test-key-not-for-production")
        src = tmp_path / "drops"
        src.mkdir()
        config = Config.model_validate(
            {
                "source": {
                    "name": "test-source",
                    "path": str(src),
                    "metadata_format": "xml",
                    "metadata_suffix": ".xml",
                    "stability_polls": 1,
                    "metadata_grace_polls": 2,
                },
                "destination": {
                    "archive": str(tmp_path / "archive"),
                    "quarantine": str(tmp_path / "quarantine"),
                    "work_dir": str(tmp_path / "work"),
                },
                "dlp": {"rules": [{"include": str(DEFAULT_RULES_PATH)}]},
            }
        )
        w = Watcher(config, Pipeline(config))
        pdf = src / "doc.pdf"
        pdf.write_bytes(b"content")

        assert w.discover_ready() == []  # poll 1: stable, grace_polls -> 1
        assert w.discover_ready() == []  # poll 2: grace_polls -> 2, still within (<=2)
        ready = w.discover_ready()  # poll 3: grace_polls -> 3, exceeds grace_polls=2
        assert ready == [(pdf, None)]

    def test_metadata_grace_polls_zero_claims_immediately_without_waiting(
        self, tmp_path, monkeypatch
    ):
        monkeypatch.setenv("DLPDUCK_HMAC_KEY", "test-key-not-for-production")
        src = tmp_path / "drops"
        src.mkdir()
        config = Config.model_validate(
            {
                "source": {
                    "name": "test-source",
                    "path": str(src),
                    "metadata_format": "xml",
                    "metadata_suffix": ".xml",
                    "stability_polls": 1,
                    "metadata_grace_polls": 0,
                },
                "destination": {
                    "archive": str(tmp_path / "archive"),
                    "quarantine": str(tmp_path / "quarantine"),
                    "work_dir": str(tmp_path / "work"),
                },
                "dlp": {"rules": [{"include": str(DEFAULT_RULES_PATH)}]},
            }
        )
        w = Watcher(config, Pipeline(config))
        pdf = src / "doc.pdf"
        pdf.write_bytes(b"content")

        assert w.discover_ready() == [(pdf, None)]

    def test_disappeared_file_stops_being_tracked(self, watcher):
        pdf = watcher.config.source.path / "vanishing.pdf"
        pdf.write_bytes(b"content")
        watcher.discover_ready()  # tracked, 1 stable poll
        pdf.unlink()
        assert watcher.discover_ready() == []
        assert watcher._tracked == {}



@pytest.fixture
def fast_watcher(tmp_path, monkeypatch):
    """A watcher tuned for driving run_forever in a test: claims on the
    first sighting and polls without a real sleep between iterations."""
    monkeypatch.setenv("DLPDUCK_HMAC_KEY", "test-key-not-for-production")
    src = tmp_path / "drops"
    src.mkdir()
    config = Config.model_validate(
        {
            "source": {
                "name": "test-source",
                "path": str(src),
                "metadata_format": "none",
                "stability_polls": 1,
                "poll_seconds": 0.01,
            },
            "destination": {
                "archive": str(tmp_path / "archive"),
                "quarantine": str(tmp_path / "quarantine"),
                "work_dir": str(tmp_path / "work"),
            },
            "dlp": {"rules": [{"include": str(DEFAULT_RULES_PATH)}]},
        }
    )
    pipeline = Pipeline(config)
    return Watcher(config, pipeline), pipeline, config


def _real_pdf(path: Path, lines: list[str]) -> Path:
    from tests.pdf_factory import write_pdf

    return write_pdf(path, lines)


class TestDaemonLoopResilience:
    """run_forever is the daemon's whole life. A single unprocessable
    document must not end it — a poisoned file in the drop folder that
    stopped ingestion for everything behind it would be a denial of
    service on the entire pipeline.
    """

    def test_one_failing_document_does_not_stop_the_loop(self, fast_watcher):
        import threading

        # Default mode (claim_only=False): the watcher claims AND
        # extracts inline, exactly as it always has.
        watcher, pipeline, config = fast_watcher
        _real_pdf(config.source.path / "poison.pdf", ["first"])
        _real_pdf(config.source.path / "good.pdf", ["second"])

        seen: list[Path] = []
        stop = threading.Event()
        real_run_job = pipeline.run_job

        def _explode_on_first(pdf_path, meta_path, staging_root):
            seen.append(pdf_path)
            if pdf_path.name == "poison.pdf":
                raise RuntimeError("something went badly wrong for this one document")
            result = real_run_job(pdf_path, meta_path, staging_root)
            stop.set()  # the healthy one made it through; end the loop
            return result

        pipeline.run_job = _explode_on_first
        watcher.run_forever(stop_event=stop)

        assert {p.name for p in seen} == {"poison.pdf", "good.pdf"}
        # the healthy document was still archived despite its neighbour
        assert list(config.destination.archive.glob("dt=*/*.pdf"))

    def test_a_stop_event_set_up_front_means_the_loop_never_runs(self, fast_watcher):
        import threading

        watcher, _pipeline, config = fast_watcher
        _real_pdf(config.source.path / "doc.pdf", ["content"])

        stop = threading.Event()
        stop.set()
        watcher.run_forever(stop_event=stop)

        assert not list(config.destination.archive.glob("dt=*/*.pdf"))


class TestLeaderGating:
    """Claiming is the one thing that isn't safe from more than one
    watcher at once (see dlpduck.leader) — a standby replica must never
    call stage(), even when files are sitting there ready."""

    def test_a_standby_watcher_never_stages_anything(self, fast_watcher):
        import threading

        watcher, _pipeline, config = fast_watcher
        watcher._is_leader = lambda: False
        _real_pdf(config.source.path / "doc.pdf", ["content"])

        stop = threading.Event()
        threading.Timer(0.05, stop.set).start()
        watcher.run_forever(stop_event=stop)

        assert not list((config.destination.work_dir / "_processing").glob("*/document.pdf"))

    def test_becoming_leader_mid_run_starts_staging(self, fast_watcher):
        import threading

        watcher, _pipeline, config = fast_watcher
        watcher._claim_only = True  # otherwise a committed job leaves _processing/ entirely
        is_leader = {"value": False}
        watcher._is_leader = lambda: is_leader["value"]
        _real_pdf(config.source.path / "doc.pdf", ["content"])

        stop = threading.Event()

        def _flip_then_stop():
            is_leader["value"] = True
            threading.Timer(0.1, stop.set).start()

        threading.Timer(0.05, _flip_then_stop).start()
        watcher.run_forever(stop_event=stop)

        assert list((config.destination.work_dir / "_processing").glob("*/document.pdf"))


class TestClaimOnlyMode:
    """cluster.parallel_extraction opts into this: the watcher claims but
    never extracts, leaving that to a sweep run elsewhere (cli.py)."""

    def test_ready_files_are_staged_but_never_processed(self, fast_watcher):
        watcher, pipeline, config = fast_watcher
        watcher._claim_only = True
        _real_pdf(config.source.path / "doc.pdf", ["content"])

        import threading
        stop = threading.Event()
        threading.Timer(0.1, stop.set).start()
        watcher.run_forever(stop_event=stop)

        staged = list((config.destination.work_dir / "_processing").glob("*/document.pdf"))
        assert staged
        assert not list(config.destination.archive.glob("dt=*/*.pdf"))

    def test_one_failing_claim_does_not_stop_the_loop(self, fast_watcher):
        import threading

        watcher, pipeline, config = fast_watcher
        watcher._claim_only = True
        _real_pdf(config.source.path / "poison.pdf", ["first"])
        _real_pdf(config.source.path / "good.pdf", ["second"])

        seen: list[Path] = []
        stop = threading.Event()
        real_stage = pipeline.stage

        def _explode_on_first(pdf_path, meta_path, staging_root):
            seen.append(pdf_path)
            if pdf_path.name == "poison.pdf":
                raise RuntimeError("something went badly wrong for this one document")
            result = real_stage(pdf_path, meta_path, staging_root)
            stop.set()
            return result

        pipeline.stage = _explode_on_first
        watcher.run_forever(stop_event=stop)

        assert {p.name for p in seen} == {"poison.pdf", "good.pdf"}
        assert list((config.destination.work_dir / "_processing").glob("*/document.pdf"))


class TestVanishingFiles:
    def test_a_file_that_disappears_between_listing_and_stat_is_skipped(self, watcher, monkeypatch):
        """The drop folder is shared; another process can move a file out
        from under the poll. That is ordinary, not an error."""
        doomed = watcher.config.source.path / "vanishing.pdf"
        doomed.write_bytes(b"content")

        real_stat = Path.stat

        def _vanish(self, *args, **kwargs):
            if self.name == "vanishing.pdf":
                raise FileNotFoundError(self)
            return real_stat(self, *args, **kwargs)

        monkeypatch.setattr(Path, "stat", _vanish)
        assert watcher.discover_ready() == []


class TestShutdownIsPrompt:
    def test_a_stop_signal_does_not_wait_out_the_poll_interval(self, tmp_path, monkeypatch):
        """A SIGTERM one second into a 30-second poll must not hold
        shutdown open for the other 29 — long enough for an init system
        to escalate to SIGKILL, which is how a job gets killed mid-write."""
        import threading
        import time

        monkeypatch.setenv("DLPDUCK_HMAC_KEY", "test-key-not-for-production")
        src = tmp_path / "drops"
        src.mkdir(exist_ok=True)
        config = Config.model_validate(
            {
                "source": {
                    "name": "test-source",
                    "path": str(src),
                    "metadata_format": "none",
                    "poll_seconds": 30,
                },
                "destination": {
                    "archive": str(tmp_path / "archive"),
                    "quarantine": str(tmp_path / "quarantine"),
                    "work_dir": str(tmp_path / "work"),
                },
                "dlp": {"rules": [{"include": str(DEFAULT_RULES_PATH)}]},
            }
        )
        watcher = Watcher(config, Pipeline(config))

        stop_event = threading.Event()
        threading.Timer(0.1, stop_event.set).start()

        started = time.monotonic()
        watcher.run_forever(stop_event)
        elapsed = time.monotonic() - started

        assert elapsed < 5, f"took {elapsed:.1f}s to stop with poll_seconds=30"
