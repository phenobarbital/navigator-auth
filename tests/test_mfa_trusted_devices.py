"""TrustedDeviceStore tests for FEAT-106 TASK-133."""

from navigator_auth.mfa.trusted_devices import may_offer_trusted_device


def test_trusted_device_not_offered_to_email_state():
    """Trusted devices require a strong factor and a positive window."""
    assert may_offer_trusted_device(has_strong_factor=True, remember_days=30)
    assert not may_offer_trusted_device(has_strong_factor=False, remember_days=30)
    assert not may_offer_trusted_device(has_strong_factor=True, remember_days=0)
