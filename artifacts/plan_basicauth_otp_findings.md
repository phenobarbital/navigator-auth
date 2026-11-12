# Apply BasicAuth OTP review findings

Scope: amend sdd/specs/basicauth-otp-2fa.spec.md only; preserve its approved status.

1. Specify protected seed storage and safe pending enrollment.
2. Define challenge invalidation, retry accounting, and HTTP exception propagation.
3. Enforce the privileged-user invariant at login and document recovery.
4. Replace dataclass contracts with frozen Pydantic v2 models.
5. Align diagrams, module scope, tests, acceptance criteria, risks, and documentation.

Assumption: the requested fixes apply to the reviewed specification, not feature implementation.
Risk: duplicated contracts can drift; validate cross-references and contradictory wording.
Validation: focused text inspection and git diff --check; runtime tests do not apply.
