from navigator_auth.handlers.users.passwd import set_basic_password
from navigator_auth.models import User


class TestRecoveryConfig:
    def test_defaults(self):
        from navigator_auth import conf
        assert conf.AUTH_RECOVERY_TTL == 3600
        assert conf.AUTH_RECOVERY_CONFIRM_TTL == 900
        assert conf.AUTH_RECOVERY_RATE_EMAIL == "3/hour"
        assert conf.AUTH_RECOVERY_RATE_IP == "10/hour"
        assert conf.AUTH_RECOVERY_PWD_MIN_LENGTH == 8

    def test_secret_falls_back_to_secret_key(self):
        from navigator_auth import conf
        assert conf.AUTH_RECOVERY_SECRET
        assert isinstance(conf.AUTH_RECOVERY_SECRET, bytes)


class TestUserPasswordWidth:
    def test_user_password_column_fits_hash(self):
        """A real PBKDF2 hash (77 chars) must fit the declared max."""
        h = set_basic_password("correct horse battery staple")
        assert len(h) == 77
        col = User.get_columns()["password"]
        assert col.metadata.get("max", 0) >= len(h)

    def test_hash_roundtrips_through_model(self):
        h = set_basic_password("correct horse battery staple")
        u = User(user_id=1, username="t", password=h)
        assert u.password == h
        assert u.is_valid()


class TestNotificationPayloadSecrecy:
    def test_repr_hides_token(self):
        from navigator_auth.handlers.recovery.types import NotificationPayload
        import datetime
        p = NotificationPayload(
            email="a@b.c", display_name="A", username="a",
            token="SUPERSECRETTOKEN", url="https://x/?token=SUPERSECRETTOKEN",
            expires_at=datetime.datetime.now(), found=True,
        )
        assert "SUPERSECRETTOKEN" not in repr(p)
