"""Checksum validators. Turn a pattern that matches any digit-run into one
that actually recognises the identifier it claims to.

Register your own with the @validator decorator — see the design doc §7.2.
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


@validator("luhn")
def luhn(s: str) -> bool:
    digits = [int(c) for c in s if c.isdigit()]
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
    digits = [int(c) for c in s if c.isdigit()]
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
