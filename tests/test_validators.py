import pytest

from dlpduck.validators import VALIDATORS, get_validator, iban_mod97, luhn, nhs_mod11, validator


class TestLuhn:
    def test_valid_test_card_number(self):
        assert luhn("4111111111111111") is True

    def test_single_digit_flip_fails(self):
        assert luhn("4111111111111112") is False

    def test_too_short_is_rejected_outright(self):
        # This is the case v1's bare digit-run regex would have quarantined
        # constantly: any 13-19 digit run, checksum or not.
        assert luhn("1234") is False

    def test_accepts_separators(self):
        assert luhn("4111 1111 1111 1111") is True
        assert luhn("4111-1111-1111-1111") is True


class TestIban:
    def test_valid_test_iban(self):
        assert iban_mod97("GB29NWBK60161331926819") is True

    def test_mutated_digit_fails(self):
        assert iban_mod97("GB29NWBK60161331926818") is False

    def test_too_short(self):
        assert iban_mod97("GB29") is False


class TestNhsMod11:
    def test_valid_test_number(self):
        assert nhs_mod11("9434765919") is True

    def test_mutated_check_digit_fails(self):
        assert nhs_mod11("9434765918") is False

    def test_wrong_length(self):
        assert nhs_mod11("12345") is False

    def test_check_digit_of_10_is_never_valid(self):
        # 100000001 computes to a check value of 10 under the published
        # algorithm, which makes the number invalid outright regardless of
        # what the 10th digit is — it never wraps to 0.
        assert nhs_mod11("1000000010") is False
        assert nhs_mod11("1000000011") is False


class TestRegistry:
    def test_none_always_passes(self):
        assert VALIDATORS["none"]("anything") is True

    def test_unknown_validator_raises_with_known_list(self):
        with pytest.raises(ValueError, match="luhn"):
            get_validator("not_a_real_validator")

    def test_custom_validator_registers(self):
        @validator("always_false_for_test")
        def _v(s: str) -> bool:
            return False

        assert get_validator("always_false_for_test")("x") is False
        del VALIDATORS["always_false_for_test"]  # don't leak into other tests


class TestChecksumEdgeCases:
    """These run on every regex match, so a branch that raises would fail
    an otherwise-fine document. The interesting cases are the ones a real
    corpus produces: doubled digits over 9, the NHS check digit of 10
    (which is never valid), and an IBAN whose letters don't transliterate."""

    def test_luhn_doubling_carries_correctly(self):
        # 4111111111111111 exercises the ">9 so subtract 9" branch.
        assert luhn("4111111111111111") is True
        assert luhn("4111111111111112") is False

    def test_luhn_rejects_a_non_numeric_candidate(self):
        assert luhn("not-a-card-number") is False

    def test_iban_with_untransliterable_characters_is_rejected(self):
        # Letters map to digits; anything left non-numeric must not raise.
        assert iban_mod97("GB29 NWBK 6016 1331 9268 19") is True
        assert iban_mod97("GB29-NWBK-!!!!-1331-9268-19") is False

    def test_iban_too_short_is_rejected(self):
        assert iban_mod97("GB") is False
        assert iban_mod97("") is False

    def test_nhs_check_digit_of_ten_is_never_valid(self):
        """remainder 1 gives check digit 10, which no NHS number has —
        the branch exists so such a candidate is rejected, not accepted."""
        rejected_any = False
        for candidate in (f"{n:010d}" for n in range(0, 4000)):
            digits = [int(d) for d in candidate]
            total = sum(d * w for d, w in zip(digits[:9], range(10, 1, -1), strict=True))
            if 11 - (total % 11) == 10:
                assert nhs_mod11(candidate) is False
                rejected_any = True
        assert rejected_any, "no candidate exercised the check-digit-10 branch"

    def test_nhs_check_digit_of_eleven_becomes_zero(self):
        found = False
        for candidate in (f"{n:010d}" for n in range(0, 4000)):
            digits = [int(d) for d in candidate]
            total = sum(d * w for d, w in zip(digits[:9], range(10, 1, -1), strict=True))
            if 11 - (total % 11) == 11:
                found = True
                assert nhs_mod11(candidate) is (digits[9] == 0)
        assert found, "no candidate exercised the check-digit-11 branch"

    def test_nhs_rejects_wrong_length(self):
        assert nhs_mod11("123") is False
        assert nhs_mod11("12345678901234") is False
