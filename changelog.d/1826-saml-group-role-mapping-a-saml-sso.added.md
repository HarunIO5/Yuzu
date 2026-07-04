- **SAML group→role mapping.** A SAML SSO session is now promoted to `role=admin` when the
  assertion's IdP-attested groups contain the configured admin group — mirroring the OIDC
  `admin_group_id` guard exactly (shared `resolve_role_from_groups` helper). Two new flags /
  env vars: `--saml-group-attribute` (`YUZU_SAML_GROUP_ATTRIBUTE`, the `<Attribute Name="...">`
  carrying group values) and `--saml-admin-group` (`YUZU_SAML_ADMIN_GROUP`, the exact group
  value that maps to admin; leading/trailing whitespace is trimmed). Both empty ⇒ unchanged
  thin-slice behaviour (every SAML login is `role=user`). Matching is exact (case-sensitive, no
  substring/prefix match) against groups read from the SAME XSW-signature-verified assertion node
  the NameID is read from — never a document-wide search — and bounded to 64 values (DoS guard).
  Unlike OIDC, SAML group values are **not** synced into `rbac_store` — they feed the
  admin/user role decision only (group-scoped RBAC assignments do not apply to SAML
  principals) — deferred pending source-aware group resolution, see issue #1832 — see
  `docs/auth-architecture.md` "SAML 2.0 SP", `docs/user-manual/authentication.md` "SAML 2.0 SSO",
  `docs/user-manual/server-admin.md`, and the security review
  `docs/security-reviews/saml-sp-2026-07-01.md`.

- **SAML/OIDC SSO login observability parity (#1828–#1830).** `yuzu_auth_saml_login_total` gained a
  `role` label (`admin`/`user`); OIDC's `/auth/callback` now emits the matching
  `yuzu_auth_oidc_login_total{result,role}` counter (previously silent). A new
  `yuzu_saml_group_cap_truncated_total` counter increments when an assertion's group-attribute
  values exceed the 64-value cap. A one-shot `config.admin_group_set` startup audit row now fires
  for either `--oidc-admin-group` or `--saml-admin-group` when configured. `--oidc-admin-group` is
  now trimmed of leading/trailing whitespace at load (closing the same silent-lockout bug already
  fixed for `--saml-admin-group`), and the OIDC admin audit detail now names the granting group
  (`admin_group=<value>`), mirroring the SAML audit detail.

- **SAML 2.0 SP — thin first slice.** SP-initiated login against a single, statically-pinned IdP.
  HTTP-Redirect binding for the `AuthnRequest`; HTTP-POST binding at the Assertion Consumer Service
  (`POST /saml/acs`). Assertion signature is validated against the pinned IdP cert (in-document
  `<KeyInfo>` ignored); XML signature-wrapping attacks are defended; audience, recipient, and
  expiry are validated; `InResponseTo` is solicited-only and single-use (replay-protected). Sessions
  are ephemeral (`auth_source="saml"`; `role=user` unless promoted to admin by group mapping — see
  above). **Linux and macOS only** — Windows fails closed at startup. Five new flags / env vars:
  `--saml-idp-entity-id` (`YUZU_SAML_IDP_ENTITY_ID`), `--saml-idp-sso-url`
  (`YUZU_SAML_IDP_SSO_URL`), `--saml-idp-cert` (`YUZU_SAML_IDP_CERT`), `--saml-sp-entity-id`
  (`YUZU_SAML_SP_ENTITY_ID`), `--saml-sp-acs-url` (`YUZU_SAML_SP_ACS_URL`). Audit:
  `auth.saml_login` (result=ok) / `auth.saml_login_failed` (result=error). Partially closes
  `/auth-and-authz` gap-matrix P1 #6. Fast-follow work (observability, proxy-TLS/HA, IdP metadata,
  AuthnRequest signing, hardening) is tracked in #1789. See `docs/auth-architecture.md`
  "SAML 2.0 SP", `docs/user-manual/authentication.md` "SAML 2.0 SSO", and the security review
  `docs/security-reviews/saml-sp-2026-07-01.md`.
