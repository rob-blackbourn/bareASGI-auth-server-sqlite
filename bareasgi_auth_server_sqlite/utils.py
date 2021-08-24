"""ISO 8601 duration"""

from datetime import timedelta
import re
from typing import Optional

# pylint: disable=line-too-long
DURATION_REGEX = re.compile(
    r'^(-?)P(?=\d|T\d)(?:(\d+)Y)?(?:(\d+)M)?(?:(\d+)([DW]))?(?:T(?:(\d+)H)?(?:(\d+)M)?(?:(\d+(?:\.\d+)?)S)?)?$'
)

DAYS_IN_MONTH = 30
DAYS_IN_YEAR = DAYS_IN_MONTH * 12
SECONDS_IN_MINUTE = 60
SECONDS_IN_HOUR = 60 * 60
SECONDS_IN_DAY = 24 * SECONDS_IN_HOUR


def _parse_int(value: Optional[str]) -> int:
    return 0 if not value else int(value)


def _parse_sign(value: Optional[str]) -> int:
    return -1 if value == '-' else 1


def parse_duration(duration: str) -> timedelta:
    """Convert an ISO 8601 duration to a timedelta

    Args:
        duration (str): An ISO 8601 format duration

    Returns:
        Optional[timedelta]: The duration as a timedelta
    """
    match = DURATION_REGEX.match(duration)
    if not match:
        raise ValueError(f'Unable to convert "{duration}" to a timedelta.')
    sign = _parse_sign(match.group(1))
    years = _parse_int(match.group(2))
    months = _parse_int(match.group(3))
    days_or_weeks = _parse_int(match.group(4))
    is_weeks = match.group(5) == 'W'
    hours = _parse_int(match.group(6))
    minutes = _parse_int(match.group(7))
    seconds = _parse_int(match.group(8))

    total_days = days_or_weeks * 7 if is_weeks else days_or_weeks
    total_days += months * DAYS_IN_MONTH
    total_days += years * DAYS_IN_YEAR

    total_seconds = seconds
    total_seconds += minutes * SECONDS_IN_MINUTE
    total_seconds += hours * SECONDS_IN_HOUR
    total_seconds += total_days * SECONDS_IN_DAY

    total_seconds *= sign

    return timedelta(seconds=total_seconds)
