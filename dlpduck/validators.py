"""Checksum validators. Turn a pattern that matches any digit-run into one
that actually recognises the identifier it claims to.

Register custom validators with the @validator decorator.
"""

from __future__ import annotations

from collections.abc import Callable

VALIDATORS: dict[str, Callable[[str], bool]] = {"none": lambda s: True}


def validator(name: str):
    def wrap(fn: Callable[[str], bool]) -> Callable[[str], bool]:
        VALIDATORS[name] = fn
        return fn

    return wrap


def get_validator(name: str) -> Callable[[str], bool]:
    try:
        return VALIDATORS[name]
    except KeyError:
        known = ", ".join(sorted(VALIDATORS))
        raise ValueError(f"unknown validator {name!r} — known validators: {known}") from None


def _digits(s: str) -> list[int]:
    r"""The decimal digits in `s`, as ints.

    isdecimal(), not isdigit(): isdigit() also accepts superscripts and
    circled digits, which int() refuses — a custom rule matching "²" made
    the validator raise and took the whole scan down with it. Decimal
    digits from other scripts (Arabic-Indic, full-width) are kept: they are
    real digits, `\d` matches them, and int() reads them correctly.
    """
    return [int(c) for c in s if c.isdecimal()]


@validator("luhn")
def luhn(s: str) -> bool:
    digits = _digits(s)
    if not 13 <= len(digits) <= 19:
        return False
    total = 0
    for i, n in enumerate(reversed(digits)):
        if i % 2 == 1:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return total % 10 == 0


@validator("iban_mod97")
def iban_mod97(s: str) -> bool:
    value = "".join(c for c in s if c.isalnum()).upper()
    if len(value) < 15 or len(value) > 34:
        return False
    # IBANs are ASCII by definition. int(c, 36) raised on any other letter
    # (an accented capital from OCR, say), and that escaped the scan.
    if not value.isascii():
        return False
    rearranged = value[4:] + value[:4]
    digits = "".join(
        str(int(c, 36)) if c.isalpha() else c for c in rearranged
    )
    try:
        return int(digits) % 97 == 1
    except ValueError:
        return False


@validator("nhs_mod11")
def nhs_mod11(s: str) -> bool:
    digits = _digits(s)
    if len(digits) != 10:
        return False
    weights = range(10, 1, -1)  # 10..2
    total = sum(d * w for d, w in zip(digits[:9], weights, strict=True))
    remainder = total % 11
    check = 11 - remainder
    if check == 11:
        check = 0
    if check == 10:
        return False  # not a valid NHS number under the published algorithm
    return check == digits[9]
