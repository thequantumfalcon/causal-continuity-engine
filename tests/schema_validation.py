"""Fail-closed JSON Schema validation used by the repository test harness.

JSON Schema ``format`` is annotation-only in many validators.  jsonschema's
RFC 3339 implementation is also an optional package, so ``FormatChecker()``
can silently stop checking calendar dates in an otherwise hash-locked clean
environment.  This module installs the repository's stdlib implementation on
every validator and self-tests that the assertion is active.
"""

from __future__ import annotations

import calendar
import re

from jsonschema import Draft202012Validator, FormatChecker

_RFC3339_DATE_TIME = re.compile(
    r"([0-9]{4})-(0[1-9]|1[0-2])-([0-9]{2})[Tt]"
    r"(?:[01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9]"
    r"(?:\.[0-9]+)?(?:[Zz]|[+-](?:[01][0-9]|2[0-3]):[0-5][0-9])\Z"
)


def stdlib_rfc3339_datetime(instance: object) -> bool:
    """Validate the RFC 3339 profile used by JSON Schema ``date-time``.

    Type validation remains the schema's job.  Leap seconds are deliberately
    unsupported, matching the established jsonschema optional checker and the
    two CCE proof implementations.
    """
    if not isinstance(instance, str):
        return True
    match = _RFC3339_DATE_TIME.fullmatch(instance)
    if match is None:
        return False
    year, month, day = map(int, match.groups())
    if year == 0:
        return False
    try:
        return 1 <= day <= calendar.monthrange(year, month)[1]
    except (ValueError, OverflowError):
        return False


def repository_format_checker() -> FormatChecker:
    """Return a checker whose date-time assertion cannot disappear silently."""
    checker = FormatChecker()
    checker.checks("date-time")(stdlib_rfc3339_datetime)
    if (
        checker.conforms("2026-02-30T04:05:06.123456Z", "date-time")
        or not checker.conforms("2024-02-29T04:05:06.123456Z", "date-time")
    ):
        raise RuntimeError("repository RFC 3339 format assertion is inactive")
    return checker


def draft202012_validator(schema: dict, **kwargs) -> Draft202012Validator:
    """Build a checked Draft 2020-12 validator with owned format assertions."""
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(
        schema, format_checker=repository_format_checker(), **kwargs)
