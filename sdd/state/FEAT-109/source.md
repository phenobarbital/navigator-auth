---
kind: inline
jira_key: null
fetched_at: 2026-11-11T14:40:00Z
summary_oneline: "PBAC example (policy_server.py): unauth-path warnings, short HMAC key warning, vault integrity error, 428 deny on /dashboard/"
---

policy-issues -- minor issues testing PBAC Example at `python examples/policy_server.py`

* warnings at middleware:
```
[WARNING] 2026-11-11 14:27:10,443 root(middleware.py:43) :: Access to /.well-known/appspecific/com.chrome.devtools.json is not Authenticated.
[WARNING] 2026-11-11 14:27:10,516 root(middleware.py:43) :: Access to /client-config is not Authenticated.
[WARNING] 2026-11-11 14:27:16,477 root(middleware.py:43) :: Access to /.well-known/appspecific/com.chrome.devtools.json is not Authenticated.
[WARNING] 2026-11-11 14:27:16,993 root(middleware.py:43) :: Access to /favicon.ico is not Authenticated.
```

* Warning of insecure key:
```
.venv/lib/python3.11/site-packages/jwt/api_jwt.py:147: InsecureKeyLengthWarning: The HMAC key is 6 bytes long, which is below the minimum recommended length of 32 bytes for SHA256. See RFC 7518 Section 3.2.
  return self._jws.encode(
.venv/lib/python3.11/site-packages/jwt/api_jwt.py:368: InsecureKeyLengthWarning: The HMAC key is 6 bytes long, which is below the minimum recommended length of 32 bytes for SHA256. See RFC 7518 Section 3.2.
  decoded = self.decode_complete(
```

* Integrity error at vault:
```
[ERROR] 2026-11-11 14:27:25,608 navigator.vault(session_vault.py:457) :: Vault secret failed integrity check: user=35 key=account error=UnsupportedFormatError
[INFO] 2026-11-11 14:27:25,610 navigator.vault(session_vault.py:490) :: Vault loaded for user=35: 0 secret(s), 1 integrity failure(s)
```

* Clicking on Dashboard I got an error `http://localhost:5000/dashboard/` or any other URL (was working before):
```
{"status":428,"reason":"Error: Some preconditions failed: No Matching Policies were found, Deny access."}
```
