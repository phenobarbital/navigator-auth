"""Serialized refresh of a linked identity's stored credential."""
from typing import Any, Optional

from ..exceptions import ConfigError, UserNotFound
from .store import IdentityStore
from .types import TokenResponse


async def refresh_linked_identity(
    store: IdentityStore,
    backend: Any,
    identity: Any,
    *,
    leeway: Optional[int] = None,
) -> tuple[Any, TokenResponse]:
    """Refresh one linked identity's credential, one caller per account at a time.

    Takes the backend's per-(user, external account) refresh guard, the same
    one the session-refresh path (``ExternalAuth.get_live_provider_token``)
    uses, and re-reads the row inside it. Without the guard, two concurrent
    callers (a double click, two consumers) both spend the same refresh
    token: a provider that rotates refresh tokens rejects the second call, or
    keeps only one of the two rotations.

    Args:
        store: Store the row was read from.
        backend: The provider's ``ExternalAuth`` backend; it owns the guard
            and the refresh grant.
        identity: The row as the caller read it.
        leeway: Refresh only when the credential expires within this many
            seconds. ``None`` is an explicit renew: refresh unless another
            caller already did while this one waited for the guard.

    Returns:
        ``(row, credential)``: the current row and its live credential.

    Raises:
        UserNotFound: The identity was unlinked or disabled meanwhile.
        ConfigError: No refresh token is stored.
        IdentityCredentialError: The stored credential cannot be decrypted.
    """
    provider = identity.auth_provider
    async with backend.refresh_guard(identity.user_id, identity.provider_user_id):
        current = await store.get_one(identity.user_id, identity.identity_id)
        if current is None or not getattr(current, "enabled", True):
            raise UserNotFound(f"{provider}: identity {identity.identity_id} is no longer linked")
        token = store.decrypt_credential(current)
        if leeway is None:
            if current.refreshed_at != identity.refreshed_at:
                # renewed by another caller while this one waited
                return current, token
        elif not token.is_expiring(leeway=leeway):
            return current, token
        if not token.refresh_token:
            raise ConfigError(
                f"{provider}: credential expired and no refresh token stored; "
                "the identity must be re-linked."
            )
        token = await backend.refresh_identity_tokens(token.refresh_token)
        current = await store.update_tokens(current, token)
        return current, token
