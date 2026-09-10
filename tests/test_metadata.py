import pytest

from dlpduck.metadata import (
    JsonMetadataParser,
    KeyValueTextParser,
    MetadataParseError,
    MetadataParserFactory,
    NoOpMetadataParser,
    XmlMetadataParser,
    allowlist,
)


class TestParsers:
    def test_xml(self):
        content = b"<meta><device_id>MFP-3F-04</device_id><filename>secret.pdf</filename></meta>"
        result = XmlMetadataParser().parse(content)
        assert result == {"device_id": "MFP-3F-04", "filename": "secret.pdf"}

    def test_xml_empty_input(self):
        assert XmlMetadataParser().parse(b"") == {}

    def test_json(self):
        content = b'{"device_id": "MFP-1", "page_count": 3}'
        assert JsonMetadataParser().parse(content) == {"device_id": "MFP-1", "page_count": 3}

    def test_json_empty_input(self):
        assert JsonMetadataParser().parse(b"") == {}

    def test_key_value_equals(self):
        content = b"device_id=MFP-2\nuser_id=jdoe\n"
        assert KeyValueTextParser().parse(content) == {"device_id": "MFP-2", "user_id": "jdoe"}

    def test_key_value_colon(self):
        content = b"device_id: MFP-2\n"
        assert KeyValueTextParser().parse(content) == {"device_id": "MFP-2"}

    def test_noop_always_empty(self):
        assert NoOpMetadataParser().parse(b"anything at all") == {}


class TestFactory:
    def test_known_formats(self):
        assert isinstance(MetadataParserFactory.get_parser("xml"), XmlMetadataParser)
        assert isinstance(MetadataParserFactory.get_parser("json"), JsonMetadataParser)
        assert isinstance(MetadataParserFactory.get_parser("text"), KeyValueTextParser)
        assert isinstance(MetadataParserFactory.get_parser("none"), NoOpMetadataParser)

    def test_unknown_format_falls_back_to_noop(self):
        assert isinstance(MetadataParserFactory.get_parser("carrier_pigeon"), NoOpMetadataParser)

    def test_case_insensitive(self):
        assert isinstance(MetadataParserFactory.get_parser("XML"), XmlMetadataParser)


class TestAllowlist:
    def test_only_named_keys_survive(self):
        raw = {"device_id": "MFP-1", "filename": "Smith_J_MRI_results.pdf", "user_id": "jdoe"}
        result = allowlist(raw, ["device_id", "user_id"])
        assert result == {"device_id": "MFP-1", "user_id": "jdoe"}
        assert "filename" not in result

    def test_empty_allowlist_drops_everything(self):
        assert allowlist({"device_id": "MFP-1"}, []) == {}

    def test_missing_keys_are_silently_skipped_not_errored(self):
        assert allowlist({"device_id": "MFP-1"}, ["device_id", "not_present"]) == {
            "device_id": "MFP-1"
        }


class TestXmlEntityAttacksAreRefused:
    """libexpat caps entity amplification on recent versions, but that is
    a property of the host's C library, not of DLPDuck — an older expat
    would expand these. The guard belongs here so it holds everywhere.
    """

    BILLION_LAUGHS = b"""<?xml version="1.0"?>
<!DOCTYPE lolz [
 <!ENTITY lol "lol">
 <!ENTITY lol1 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
 <!ENTITY lol2 "&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;">
]>
<root><device>&lol2;</device></root>"""

    XXE = b"""<?xml version="1.0"?>
<!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]>
<r><device>&x;</device></r>"""

    def test_entity_expansion_bomb_is_refused(self):
        with pytest.raises(MetadataParseError, match="DOCTYPE"):
            XmlMetadataParser().parse(self.BILLION_LAUGHS)

    def test_external_entity_declaration_is_refused(self):
        with pytest.raises(MetadataParseError, match="DOCTYPE"):
            XmlMetadataParser().parse(self.XXE)

    def test_doctype_detection_is_not_fooled_by_whitespace_or_case(self):
        sneaky = b'<!  doctype r [<!ENTITY x "y">]>\n<r><device>&x;</device></r>'
        with pytest.raises(MetadataParseError):
            XmlMetadataParser().parse(sneaky)

    def test_ordinary_scanner_xml_still_parses(self):
        ok = b"<meta><device_id>MFP-3F-04</device_id><department>Finance</department></meta>"
        assert XmlMetadataParser().parse(ok) == {
            "device_id": "MFP-3F-04",
            "department": "Finance",
        }


class TestNestedDocuments:
    """Neither parser understands XPath or JSONPath — allowlist()'s
    dot-path is the whole extraction language. These pin that a grandchild
    is actually reachable, not silently dropped the way XmlMetadataParser
    used to drop anything without text of its own.
    """

    def test_xml_grandchild_is_reachable_by_dot_path(self):
        content = b"<meta><device><id>MFP-1</id><site>3F</site></device></meta>"
        raw = XmlMetadataParser().parse(content)
        assert raw == {"device": {"id": "MFP-1", "site": "3F"}}
        assert allowlist(raw, ["device.id"]) == {"device.id": "MFP-1"}

    def test_repeated_xml_siblings_collect_into_a_list(self):
        content = b"<meta><owner>alice</owner><owner>bob</owner></meta>"
        assert XmlMetadataParser().parse(content) == {"owner": ["alice", "bob"]}

    def test_json_nested_field_is_reachable_by_dot_path(self):
        raw = JsonMetadataParser().parse(b'{"device": {"id": "MFP-2", "site": "4F"}}')
        assert allowlist(raw, ["device.id", "device.site"]) == {
            "device.id": "MFP-2",
            "device.site": "4F",
        }

    def test_missing_segment_is_silently_skipped_not_errored(self):
        raw = {"device": {"id": "MFP-1"}}
        assert allowlist(raw, ["device.missing", "device.id"]) == {"device.id": "MFP-1"}

    def test_a_path_through_a_non_dict_is_silently_skipped(self):
        raw = {"device": "MFP-1"}  # not nested — "device.id" has nowhere to descend
        assert allowlist(raw, ["device.id"]) == {}

    def test_output_stays_flat_keyed_by_the_literal_dotted_path(self):
        """A dot-path is not reassembled into nested output — the config
        field name, dots included, is the key a plugin actually reads."""
        raw = {"device": {"id": "MFP-1"}}
        result = allowlist(raw, ["device.id"])
        assert result == {"device.id": "MFP-1"}
        assert "device" not in result

    def test_a_whole_nested_subtree_can_still_be_kept_without_a_dot_path(self):
        raw = {"device": {"id": "MFP-1", "site": "3F"}}
        assert allowlist(raw, ["device"]) == {"device": {"id": "MFP-1", "site": "3F"}}

    def test_an_oversized_nested_subtree_is_truncated_like_a_string_value(self):
        from dlpduck.metadata import MAX_VALUE_CHARS

        raw = {"device": {"id": "A" * 100_000}}
        kept = allowlist(raw, ["device"])
        assert isinstance(kept["device"], str)
        assert len(kept["device"]) < MAX_VALUE_CHARS + 50
        assert kept["device"].endswith("[truncated]")
