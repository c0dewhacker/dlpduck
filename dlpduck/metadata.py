"""Companion metadata decoding. Printers emit metadata in varying formats;
the factory decodes into a flat dict, and the caller allowlists which keys
survive into the archive; filenames and other free text routinely
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
        return self._element_to_dict(root)

    @staticmethod
    def _element_to_dict(element: ET.Element) -> dict[str, Any]:
        """Recurse into child elements rather than reading only the root's
        direct children, so a grandchild is reachable via allowlist()'s
        dot-path rather than being silently dropped for having no text of
        its own. Mixed content on a container element is ignored — scanner
        metadata doesn't have any. Repeated sibling tags collect into a
        list; single occurrences don't pay that cost.
        """
        result: dict[str, Any] = {}
        for child in element:
            value: Any = (
                XmlMetadataParser._element_to_dict(child)
                if len(child)
                else (child.text.strip() if child.text else None)
            )
            if not value:
                continue
            if child.tag not in result:
                result[child.tag] = value
            elif isinstance(result[child.tag], list):
                result[child.tag].append(value)
            else:
                result[child.tag] = [result[child.tag], value]
        return result


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


_MISSING = object()


def _resolve(raw: dict[str, Any], path: str) -> Any:
    """A field name is a dot-path (`device.id`) descending through nested
    dicts — a plain name is just a one-segment path, so an ordinary flat
    key behaves exactly as it always did. Any segment missing, or found on
    something that isn't a dict, is "not present", the same as a flat key
    that never existed.
    """
    node: Any = raw
    for part in path.split("."):
        if not isinstance(node, dict) or part not in node:
            return _MISSING
        node = node[part]
    return node


def _bounded(value: Any) -> Any:
    if isinstance(value, str):
        if len(value) > MAX_VALUE_CHARS:
            return value[:MAX_VALUE_CHARS] + "…[truncated]"
        return value
    # A dot-path can keep a whole nested subtree (JSON nesting survives
    # parsing; XmlMetadataParser now builds one too), and that subtree is
    # not a str — cap its serialized size too, or an oversized companion
    # document reaches the permanent index untruncated just because the
    # kept value's type happens not to be a string.
    try:
        serialized = json.dumps(value)
    except TypeError:
        serialized = str(value)
    if len(serialized) > MAX_VALUE_CHARS:
        return serialized[:MAX_VALUE_CHARS] + "…[truncated]"
    return value


def allowlist(raw: dict[str, Any], fields: list[str]) -> dict[str, Any]:
    """Drop every key not explicitly named. Applied before the value ever
    reaches a JobContext. `filename` is deliberately not in any
    default list; a deployment that wants it has to say so.

    A field name may be a dot-path into a nested document (`device.id`);
    see `_resolve`. The output is still flat — kept under the literal
    field name as written in config, dots included, not reassembled into
    nested structure — so a plugin or template reads `ctx.metadata["device.id"]`
    exactly as configured, and existing flat-key deployments are unaffected.

    Surviving values are also length-capped: the allowlist decides WHICH
    untrusted fields are kept, this decides how much of one is allowed to
    be, since the index they land in is permanent.
    """
    kept = {}
    for key in fields:
        value = _resolve(raw, key)
        if value is _MISSING:
            continue
        kept[key] = _bounded(value)
    return kept
