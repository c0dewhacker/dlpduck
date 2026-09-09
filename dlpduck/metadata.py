"""Companion metadata decoding. Printers emit metadata in varying formats;
the factory decodes into a flat dict, and the caller allowlists which keys
survive into the archive (§6.4 — filenames and other free text routinely
disclose as much as the document itself, so nothing is kept by default).
"""

from __future__ import annotations

import json
import re
import xml.etree.ElementTree as ET
from abc import ABC, abstractmethod
from typing import Any


class BaseMetadataParser(ABC):
    @abstractmethod
    def parse(self, content: bytes) -> dict[str, Any]:
        ...


class MetadataParseError(ValueError):
    pass


# A DOCTYPE is the entry point for every XML entity attack — billion
# laughs, quadratic blowup, and (on parsers that resolve them) external
# entity file reads. Companion metadata is flat key/value XML written by a
# scanner; it has never needed a DTD, so the safe subset is simply "no
# DOCTYPE at all".
_DOCTYPE = re.compile(rb"<!\s*DOCTYPE", re.IGNORECASE)


class XmlMetadataParser(BaseMetadataParser):
    def parse(self, content: bytes) -> dict[str, Any]:
        if not content.strip():
            return {}
        # Modern libexpat caps entity amplification itself, but that is a
        # property of whichever C library the host happens to ship, not of
        # this program. A companion file arrives from the same drop folder
        # as the PDF — semi-trusted at best — so the check belongs here,
        # where it holds on every platform.
        if _DOCTYPE.search(content):
            raise MetadataParseError(
                "companion XML declares a DOCTYPE; refusing to parse it "
                "(entity declarations are an amplification/XXE vector and are "
                "never needed for scanner metadata)"
            )
        root = ET.fromstring(content)  # noqa: S314 — DOCTYPE rejected above
        return {child.tag: child.text.strip() for child in root if child.text}


class JsonMetadataParser(BaseMetadataParser):
    def parse(self, content: bytes) -> dict[str, Any]:
        if not content.strip():
            return {}
        data = json.loads(content.decode("utf-8"))
        return data if isinstance(data, dict) else {"value": data}


class KeyValueTextParser(BaseMetadataParser):
    def parse(self, content: bytes) -> dict[str, Any]:
        data: dict[str, Any] = {}
        text = content.decode("utf-8", errors="ignore")
        for line in text.splitlines():
            if "=" in line:
                k, v = line.split("=", 1)
                data[k.strip()] = v.strip()
            elif ":" in line:
                k, v = line.split(":", 1)
                data[k.strip()] = v.strip()
        return data


class NoOpMetadataParser(BaseMetadataParser):
    def parse(self, content: bytes) -> dict[str, Any]:
        return {}


class MetadataParserFactory:
    _parsers: dict[str, type[BaseMetadataParser]] = {
        "xml": XmlMetadataParser,
        "json": JsonMetadataParser,
        "text": KeyValueTextParser,
        "none": NoOpMetadataParser,
    }

    @classmethod
    def get_parser(cls, fmt: str) -> BaseMetadataParser:
        parser_cls = cls._parsers.get(str(fmt).lower(), NoOpMetadataParser)
        return parser_cls()


# Real scanner metadata values are short. A PDF, though, declares its own
# Info dictionary, so a hostile or broken one can present a megabyte-long
# Title — which would then be stored verbatim in the index row that is
# meant to outlive a purge, and rendered into a table cell in the console.
MAX_VALUE_CHARS = 4096


def allowlist(raw: dict[str, Any], fields: list[str]) -> dict[str, Any]:
    """Drop every key not explicitly named. Applied before the value ever
    reaches a JobContext — see §6.4. `filename` is deliberately not in any
    default list; a deployment that wants it has to say so.

    Surviving values are also length-capped: the allowlist decides WHICH
    untrusted fields are kept, this decides how much of one is allowed to
    be, since the index they land in is permanent.
    """
    kept = {}
    for key in fields:
        if key not in raw:
            continue
        value = raw[key]
        if isinstance(value, str) and len(value) > MAX_VALUE_CHARS:
            value = value[:MAX_VALUE_CHARS] + "…[truncated]"
        kept[key] = value
    return kept
