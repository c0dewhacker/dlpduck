from __future__ import annotations

import pytest

from tests.pdf_factory import make_pdf


@pytest.fixture
def hmac_key() -> bytes:
    return b"test-key-not-for-production"


@pytest.fixture
def pdf_factory():
    return make_pdf
