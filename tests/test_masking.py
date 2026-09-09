from dlpduck.masking import correlate, mask


def test_default_fully_masks():
    assert mask("244138901") == "•" * 9


def test_keep_reveals_only_the_tail():
    assert mask("4111111111111111", keep=4) == "•" * 12 + "1111"


def test_short_match_never_reveals_a_tail_even_when_keep_is_set():
    # A 5-char value with keep=4 would otherwise be 80% cleartext.
    assert mask("12345", keep=4) == "•" * 5


def test_non_alnum_characters_are_dropped_before_masking():
    assert mask("4111-1111-1111-1111", keep=4) == "•" * 12 + "1111"


def test_empty_input():
    assert mask("") == ""


def test_correlate_is_stable_across_formatting():
    a = correlate("4111-1111-1111-1111", b"key")
    b = correlate("4111 1111 1111 1111", b"key")
    c = correlate("4111111111111111", b"key")
    assert a == b == c


def test_correlate_is_keyed():
    assert correlate("4111111111111111", b"key1") != correlate("4111111111111111", b"key2")


def test_correlate_never_contains_the_raw_value():
    digest = correlate("4111111111111111", b"key")
    assert "4111" not in digest
