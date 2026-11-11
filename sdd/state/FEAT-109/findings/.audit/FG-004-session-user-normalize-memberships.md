---
id: FG-004
query_id: Q014
type: git_log
intent: "Follow-up: session-user rehydration changes that could alter PBAC subject attributes"
executed_at: 2026-11-11T14:51:00Z
duration_ms: 700
parent_id: FG-003
depth: 1
---

# FG-004 — FEAT fix-organizations-orgid normalizes session-user memberships on rehydration

## Summary

On 2026-10-13 the `fix-organizations-orgid` feature (TASK-100 + review fix) made
`AuthHandler.get_session_user` call `AuthUser.normalize_memberships()` on every rehydrated
session user, and widened the swallowed exceptions to `ValueError, TypeError` (logged as
"NAV: Unable to decode User session", returning None). This is the most recent change that
alters the *subject* the PDP sees (groups/organizations) for every request, and it fits the
"was working before / any URL" pattern: if normalization reshapes or drops `groups`, or the
session user fails to decode, subject-based policies stop matching and the evaluator falls
to the deny default ("No Matching Policies"). Unconfirmed — needs a code read.

## Citations

- path: `navigator_auth/auth.py`
  lines: 737-746
  symbol: `AuthHandler.get_session_user`
  excerpt: |
    d31f568 2026-10-13 feat(fix-organizations-orgid): TASK-100 — Normalize legacy session users
                if user:
                    if isinstance(user, AuthUser):
                        user.normalize_memberships()
                    user.is_authenticated = True
    6d1fc36 2026-10-13 review fixes — fail closed on TypeError:
            except (AttributeError, RuntimeError, ValueError, TypeError) as ex:
                logging.warning(f"NAV: Unable to decode User session: {ex}")

- path: `navigator_auth/identities.py`
  lines: n/a
  symbol: `AuthUser.normalize_memberships`
  excerpt: |
    imported in auth.py by d31f568: from .identities import AuthUser

## Notes

- Also 2ae0560 (2026-10-13) black-formatted auth.py (-78/+27).
- [cross-lane: type=read, intent=read AuthUser.normalize_memberships in navigator_auth/identities.py
  and how abac/context.py builds user groups for the evaluator; compare with group names the
  example's policies require]
- [cross-lane: type=grep, intent=check the user's server log for "NAV: Unable to decode User
  session" — would mean the subject is anonymous for every request]
