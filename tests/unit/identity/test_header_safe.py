"""Unit tests for `header_safe` (FEAT-104, TASK-115)."""
import pytest

from navigator_auth.libs.sanitize import HEADER_FORBIDDEN, header_safe

PAYLOADS = [
    "boom\r\nSet-Cookie: evil=1",
    "a\x00b\x1bc\x7fd\x9fe",
    "x" * 10_000,
    "\r\n\r\n" + "ok",
    ValueError("a\nb"),
    None,
]


class TestHeaderSafe:
    def test_strips_crlf(self):
        """A CRLF payload cannot survive as a second header line."""
        out = header_safe("boom\r\nSet-Cookie: evil=1")
        assert "\r" not in out and "\n" not in out
        assert out.startswith("boom")

    def test_strips_control_characters(self):
        """NUL, ESC, DEL and the C1 range are all removed."""
        for ch in ("\x00", "\x1b", "\x7f", "\x80", "\x9f"):
            out = header_safe(f"a{ch}b")
            assert ch not in out
            assert out == "a b"

    def test_truncates(self):
        """A long input is capped at max_length."""
        assert len(header_safe("x" * 10_000)) <= 256
        assert len(header_safe("x" * 10_000, max_length=10)) == 10

    def test_sanitizes_before_truncating(self):
        """Control stripping happens first, so the cap is spent on real text."""
        out = header_safe("\r\n" * 50 + "payload", max_length=7)
        assert out == "payload"

    def test_coerces_non_str(self):
        """None -> ""; an Exception -> its str(), sanitized."""
        assert header_safe(None) == ""
        out = header_safe(ValueError("a\nb"))
        assert "\n" not in out
        assert out == "a b"

    @pytest.mark.parametrize("payload", PAYLOADS)
    def test_result_is_header_encodable(self, payload):
        """The output always survives latin-1 header encoding."""
        out = header_safe(payload)
        out.encode("latin-1")
        assert HEADER_FORBIDDEN.search(out) is None
