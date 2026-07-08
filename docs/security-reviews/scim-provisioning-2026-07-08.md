# Security review — SCIM v2 provisioning (SOC 2 CC6.2/CC6.8)

**Date:** 2026-07-08
**Change:** SCIM 2.0 (RFC 7643/7644) User provisioning — an enterprise IdP
(Okta/Entra/OneLogin) can auto-provision and auto-deprovision Yuzu operator
accounts over `/scim/v2/*`, gated by `--scim-enable`/`--scim-token`.
**Branch:** `feat/auth-scim-v2`
**Controls:** SOC 2 **CC6.2** (provisioning — accounts created through a
controlled, auditable IdP-driven process rather than ad hoc admin action),
**CC6.8** (termination — deprovisioning that reliably disables access and
revokes live sessions on IdP-side offboarding). Closes `/auth-and-authz`
gap-matrix **P1 #7** (Users slice; Groups→role mapping is a deferred
follow-up).

## What shipped

- **`--scim-enable`** (`YUZU_SCIM_ENABLE`, default `false`) + **`--scim-token`**
  (`YUZU_SCIM_TOKEN`) gate the entire `/scim/v2/*` route surface — when
  disabled, no SCIM route exists at all. Two fail-closed boot guards: (1)
  `--scim-enable` without `--scim-token` refuses to start (no way to gate an
  account-mutating surface without a credential); (2) `--scim-enable` with
  `--no-https` refuses to start (the bearer token must never cross the wire
  in plaintext). The active posture is logged once at boot for CC6.2
  evidence.
- **Bearer auth on every route, including discovery.** `Authorization: Bearer
  <token>` validated **constant-time** (`CRYPTO_memcmp`) against a SHA-256
  hash — mirrors `ApiTokenStore`'s hashing pattern (verify-only; the raw
  token is never stored). Failure is a uniform `401` +
  `WWW-Authenticate: Bearer` regardless of cause (missing header, malformed
  header, wrong token) — no oracle distinguishing "SCIM not configured" from
  "wrong token." Every authenticated call maps to a fixed `scim-service`
  audit principal, entirely separate from operator API tokens and session
  cookies.
- **Provisioning floor: `role=user`, always.** `POST /scim/v2/Users` creates
  the account at the fixed, read-only `user` role with a discarded
  CSPRNG-generated password (the account authenticates via SSO, never a
  local password). There is no field in the SCIM User schema, nor any code
  path, that can set a SCIM-provisioned account to `role=admin`. A duplicate
  `userName` is rejected `409` rather than silently upserting an existing
  account's data.
- **The provenance guard (the load-bearing invariant).** Every
  deactivate/reactivate/update/delete call re-verifies
  `provisioning_source == "scim"` (a new `users` column,
  `AuthDB::set_provisioning_source`/`get_provisioning_source`, auth.db
  migration v7) **immediately before** mutating the target account. A
  mismatch refuses with **`404`, never `403`** (a `403` is an existence
  oracle — it confirms the resource is real but protected) plus a
  `scim.user.provenance_denied` audit row, so the attempt is still
  recorded even though the caller sees a plain not-found.
- **Deprovision cascades sessions; reactivation does not resurrect MFA.**
  `active:false` (via `PATCH` or `DELETE`) soft-deletes the auth account
  **and** revokes any live session for that user — a terminated employee's
  in-flight session does not outlive the IdP's call. `active:true` restores
  the account and clears stale lockout state, but deliberately does **not**
  restore TOTP enrollment — a reactivated user re-enrolls MFA from scratch,
  so a dormant device/secret from before termination is never trusted again.
- **Storage rides `auth.db`, not a new store.** `scim_resources` (id/
  externalId ↔ username mapping) and `scim_tokens` (sha256 hashes) live
  inside the same `auth.db` file `AuthDB` manages, under their own
  `MigrationRunner` component (`"scim"`) independent of AuthDB's own
  `"auth_db"` track — so user identity stays on one substrate and rides
  `auth.db`'s eventual Postgres migration (ADR-0006) rather than needing a
  second migration path or second `.db` file.
- **Audit actions:** `scim.user.provisioned`, `.updated`, `.deactivated`,
  `.reactivated`, `.deleted`, `.provenance_denied` — all `target_type=User`.

## Threats considered

- **Compromised or misconfigured IdP connector deactivating an account it
  didn't create.** Closed by the provenance guard: the mutation re-checks
  `provisioning_source` at the mutation site (not just at lookup), and a
  mismatch is a plain `404` rather than a `403` that would confirm the
  target account's existence to an attacker probing SCIM ids.
- **Compromised IdP minting an admin account.** Closed structurally —
  `POST /scim/v2/Users` has no admin-granting field or code path; every
  SCIM-provisioned account is `role=user`.
- **Break-glass / local-admin lockout via a spoofed or malicious SCIM
  push.** Closed by the same provenance guard — the break-glass account and
  any locally-created admin have `provisioning_source != "scim"`, so no
  SCIM deactivate/delete call can ever reach them, independent of how the
  attacker obtained or guessed their SCIM-facing `id`.
- **Enumeration via response shape.** The `404`-not-`403` provenance
  response and the uniform `401` auth-failure envelope both avoid handing
  an attacker a signal distinguishing "exists but protected" from "does not
  exist," or "wrong token" from "SCIM disabled."
- **Terminated user's session outliving the IdP's deprovisioning call.**
  Closed — `active:false` cascades session revocation in the same request
  that soft-deletes the account, rather than relying on the session's own
  expiry or a separate reconciliation pass.
- **Stale MFA reused after a reactivation.** Closed — reactivation clears
  lockout but explicitly does not restore TOTP enrollment state; the
  returning user must re-enroll.
- **SCIM token replay / theft.** Standard bearer-token exposure surface,
  mitigated the same way any bearer credential is: HTTPS is mandatory (boot
  guard), the token is stored only as a verify-only hash (a `auth.db` leak
  does not disclose the raw token), and comparison is constant-time to
  avoid a timing side channel on the hash comparison itself.

## Residual risks (accepted / tracked)

- **`location_base` trusts `Host`/`X-Forwarded-Proto`.** The `Location`
  header on a `201` and the `meta.location` field in SCIM User bodies are
  built from the request's `Host`/`X-Forwarded-Proto`, which are
  client-influenceable in general. Accepted here because the caller is
  already the single authenticated IdP bearer-token holder — there is no
  additional principal this could be used to confuse, and the field is
  advisory (a client-convenience URL, not used in any authorization
  decision). Same accepted pattern as other server-constructed `Location`
  headers in the REST v1 surface.
- **No SCIM-specific rate limit.** SCIM calls share the server's global
  rate-limit only; there is no throttle tuned to expected IdP-connector call
  volume/shape. A compromised or malfunctioning connector could still hit
  the global limit but has no SCIM-specific amplification path beyond that.
  Tracked as a follow-up (`docs/auth-architecture.md` "Deferred (next
  slice)").
- **SCIM bearer token stored as a verify-only hash, not a reversible
  encrypted blob.** This is actually the *stronger* posture (nothing to
  decrypt if `auth.db` leaks), so it is not itself a gap — noted because a
  future reversible form (if ever needed for token display/rotation UX)
  would ride `auth.db`'s Postgres/`SecretCodec` migration (ADR-0010),
  alongside the TOTP-secret-at-rest follow-up.
- **Groups→role mapping is out of scope this slice.** Every
  SCIM-provisioned account is `role=user`; there is no path (by design) to
  provision or promote an admin via SCIM in this release. Tracked as the
  next SCIM slice, mirroring the OIDC/SAML group→role mechanisms.
- **`userName` rename via `PUT` is rejected, not supported.** A `400
  mutability` response requires the IdP-side workflow to delete + re-create
  rather than rename in place. No security impact — a narrower surface, not
  a gap.

## Validation

- Unit tests: `tests/unit/server/test_scim_store.cpp` (token hashing +
  constant-time validate, resource CRUD, provenance-relevant fields),
  `test_scim_json.cpp` (codec + filter parsing + discovery documents),
  `test_scim_routes.cpp` (wire path: bearer auth on every route including
  discovery, provisioning at fixed `role=user`, `409` uniqueness, `400`
  invalid filter/mutability, `404` provenance-guard rejection, deactivate/
  reactivate/delete semantics, audit rows).
- Storage layer opens its own `sqlite3` connection to the same `auth.db`
  file `AuthDB` manages, under an independent `"scim"` `MigrationRunner`
  component — verified against `migration_runner.{hpp,cpp}` not to collide
  with AuthDB's own `"auth_db"` migration track on the same file.

## Reviewer

Junior-developer implementation across three code slices (storage / JSON
codec / routes) plus this documentation and compliance-evidence pass, on
`feat/auth-scim-v2`.
