"""
Environment model for PBAC evaluation.

Provides rich environment context including day segments, business hours,
and timezone awareness for time-based access control policies.
"""
from __future__ import annotations

import datetime as _dt
import time as _time_mod
from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field

from navconfig import config


# --- Configuration (read once at import) ---

def _parse_time(value: str) -> _dt.time:
    """Parse HH:MM string to time object."""
    parts = value.strip().split(":")
    return _dt.time(int(parts[0]), int(parts[1]))


def _parse_time_range(value: str) -> tuple:
    """Parse 'HH:MM-HH:MM' string to (time, time) tuple."""
    start_str, end_str = value.split("-")
    return _parse_time(start_str), _parse_time(end_str)


# Business hours configuration
BUSINESS_HOURS_START = _parse_time(
    config.get("BUSINESS_HOURS_START", fallback="08:00")
)
BUSINESS_HOURS_END = _parse_time(
    config.get("BUSINESS_HOURS_END", fallback="18:00")
)
# ISO weekdays: 1=Mon, 7=Sun -> convert to Python weekday 0=Mon, 6=Sun
_business_days_str = config.get("BUSINESS_DAYS", fallback="1,2,3,4,5")
BUSINESS_DAYS = {int(d.strip()) - 1 for d in _business_days_str.split(",")}

# Day segment boundaries
_seg_morning = _parse_time_range(
    config.get("DAY_SEGMENT_MORNING", fallback="06:00-12:00")
)
_seg_afternoon = _parse_time_range(
    config.get("DAY_SEGMENT_AFTERNOON", fallback="12:00-18:00")
)
_seg_evening = _parse_time_range(
    config.get("DAY_SEGMENT_EVENING", fallback="18:00-22:00")
)
# Night is the complement of the other three


def _now():
    return _dt.datetime.now()


def _curtime():
    return _time_mod.time()


def _today():
    return _dt.date.today()


class DaySegment(str, Enum):
    """Day segment classification for time-based policies."""
    MORNING = "morning"
    AFTERNOON = "afternoon"
    EVENING = "evening"
    NIGHT = "night"


class Environment(BaseModel):
    """Rich environment context for PBAC evaluation.

    Provides time-based attributes for policy conditions including
    day segments, business hours detection, and weekend awareness.

    Attributes:
        time: Current Unix timestamp.
        timestamp: Current datetime.
        dow: Day of week (0=Monday, 6=Sunday).
        day_of_week: Alias for dow.
        hour: Current hour (0-23).
        minute: Current minute (0-59).
        date: Current date.
        day_segment: Current segment of the day (morning/afternoon/evening/night).
        is_business_hours: Whether current time falls within configured business hours.
        is_weekend: Whether today is Saturday or Sunday.
        timezone: Timezone name (informational).
    """
    time: float = Field(default_factory=_curtime)
    timestamp: _dt.datetime = Field(default_factory=_now)
    dow: Optional[int] = None
    day_of_week: Optional[int] = None
    hour: Optional[int] = None
    minute: Optional[int] = None
    date: _dt.date = Field(default_factory=_today)
    day_segment: DaySegment = DaySegment.MORNING
    is_business_hours: bool = False
    is_weekend: bool = False
    timezone: str = "UTC"

    model_config = {"arbitrary_types_allowed": True}

    def model_post_init(self, __context) -> None:
        # Resolve hour/minute: use explicit value if provided, else from timestamp
        if self.hour is None:
            self.hour = self.timestamp.hour
        if self.minute is None:
            self.minute = self.timestamp.minute

        # Resolve day of week: explicit value wins, else from timestamp
        if self.dow is not None:
            self.day_of_week = self.dow
        elif self.day_of_week is not None:
            self.dow = self.day_of_week
        else:
            self.dow = self.timestamp.weekday()
            self.day_of_week = self.dow

        self.date = self.timestamp.date()
        self.is_weekend = self.dow >= 5
        self.day_segment = self._compute_segment()
        self.is_business_hours = self._compute_business_hours()

    def _compute_segment(self) -> DaySegment:
        """Compute the day segment based on configured boundaries."""
        current = _dt.time(self.hour, self.minute)
        if _seg_morning[0] <= current < _seg_morning[1]:
            return DaySegment.MORNING
        if _seg_afternoon[0] <= current < _seg_afternoon[1]:
            return DaySegment.AFTERNOON
        if _seg_evening[0] <= current < _seg_evening[1]:
            return DaySegment.EVENING
        return DaySegment.NIGHT

    def _compute_business_hours(self) -> bool:
        """Check if current time falls within configured business hours."""
        if self.dow not in BUSINESS_DAYS:
            return False
        current = _dt.time(self.hour, self.minute)
        return BUSINESS_HOURS_START <= current < BUSINESS_HOURS_END

    # --- Backward compatibility with dict-like access ---
    def __getitem__(self, key: str):
        """Support dict-like access for backward compatibility."""
        try:
            return getattr(self, key)
        except AttributeError:
            raise KeyError(key)

    def __contains__(self, key: str) -> bool:
        return hasattr(self, key)

    def items(self):
        """Return items for dict-like iteration."""
        return self.model_dump().items()

    def get(self, key: str, default=None):
        """Dict-like get method."""
        return getattr(self, key, default)
