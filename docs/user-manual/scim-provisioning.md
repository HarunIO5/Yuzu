# SCIM v2 Provisioning

SCIM 2.0 (System for Cross-domain Identity Management, RFC 7643/7644) lets
an enterprise identity provider — Okta, Microsoft Entra ID, OneLogin, and
others — automatically create and disable Yuzu operator accounts as people
join, move, and leave your organization, instead of an admin managing
accounts by hand in the dashboard. This is the standard mechanism auditors
look for when assessing SOC 2 **CC6.2** (provisioning) and **CC6.8**
(termination).

> **Users-only in this release.** Groups→role mapping (granting `role=admin`
> via IdP-attested group membership, the way [SAML](authentication.md#saml-group-to-role-mapping)
> and OIDC already support) is a deferred follow-up. Every SCIM-provisioned
> account is created at the fixed, read-only `user` role — see
> [What gets provisioned](#what-gets-provisioned) below.

## What SCIM does

Once enabled, your IdP's SCIM connector talks to `https://<your-server>/scim/v2`
using a bearer token you configure. From then on:

- **New hire assigned the Yuzu app in the IdP** → the IdP calls
  `POST /scim/v2/Users` → a Yuzu account is created automatically, ready to
  sign in via SSO.
- **Employee terminated / unassigned from the app in the IdP** → the IdP
  calls `PATCH` (or `DELETE`) → the Yuzu account is disabled immediately,
  and any active session for that user is revoked. No admin has to remember
  to go disable the account by hand.
- **Employee later re-assigned / re-hired** → the IdP re-activates the same
  SCIM resource → the Yuzu account is restored (any stale account lockout
  is cleared). The user re-enrolls MFA on their next login — a reactivation
  never resurrects an old second factor.

## Enabling SCIM

Two flags, both required together:

| Flag | Env var | Description |
|---|---|---|
| `--scim-enable` | `YUZU_SCIM_ENABLE` | Turns on the `/scim/v2/*` endpoint surface. Default `false` — the surface does not exist at all until you opt in. |
| `--scim-token` | `YUZU_SCIM_TOKEN` | The bearer credential your IdP's SCIM connector will authenticate with. Generate a long random secret and treat it like a password (a 32+ byte random hex/base64 string is a good choice). |

```bash
./yuzu-server \
  --https-cert    /etc/yuzu/server.crt \
  --https-key     /etc/yuzu/server.key \
  --scim-enable \
  --scim-token    "$(openssl rand -hex 32)"
```

**The server refuses to start** in either of these cases:

- `--scim-enable` is set but `--scim-token` is not — there is no safe way
  to expose the provisioning surface without a credential gating it.
- `--scim-enable` is set together with `--no-https` — the bearer token is a
  credential capable of creating and disabling operator accounts; it must
  never be sent in plaintext. **SCIM requires HTTPS.**

The server logs its SCIM posture once at startup so you have a record of
when provisioning was turned on (compliance evidence for CC6.2).

## Configuring your IdP's SCIM connector

Point your IdP's SCIM connector at the base URL and supply the bearer token:

- **SCIM base URL:** `https://yuzu.example.com/scim/v2`
- **Authentication:** Bearer token — enter the same value you set with
  `--scim-token`.

Consult your IdP's SCIM setup documentation for the exact steps (Okta:
"SCIM Provisioning" app integration wizard; Entra ID: "Provisioning" tab on
the Enterprise Application). Yuzu implements the standard discovery
endpoints (`ServiceProviderConfig`, `ResourceTypes`, `Schemas`) that most
connector wizards use to auto-detect capabilities — after entering the base
URL and token, use your IdP's "Test Connection" button to confirm the
handshake works before assigning any users.

Once connected, assign users/groups to the Yuzu application in your IdP as
you would for any other SCIM-provisioned app; the IdP handles the
create/update/deactivate calls automatically from that point on.

## What gets provisioned

A user created via SCIM:

- Is assigned the **`user` role** (read-only, floor privilege) — regardless
  of any group or role attribute the IdP might send. There is no way for a
  SCIM push to create or promote an admin account in this release.
- Gets a **random, discarded password** — SCIM users never log in with a
  local password. They authenticate through your SSO flow (OIDC or SAML)
  the same as any other SSO user.
- Is tracked with a **provisioning source of "scim"**. This matters for
  deprovisioning safety (see below): a locally-created admin account, or
  the emergency break-glass account, can never be touched by a SCIM
  deactivate/delete call — even if the IdP or connector is compromised or
  misconfigured. A SCIM push can only ever affect accounts it created.

If you need admin access for a person managed via your IdP today, grant it
through [OIDC group→role mapping](authentication.md#group-to-role-mapping)
or [SAML group→role mapping](authentication.md#saml-group-to-role-mapping) —
those are independent of SCIM and unaffected by this feature.

## Deprovisioning and termination

When your IdP deactivates or removes a user's app assignment, it sends a
`PATCH` (setting `active: false`) or a `DELETE`. Either way:

- The Yuzu account is disabled immediately.
- Any session the user currently holds is revoked — they are logged out,
  not just blocked from a future login.
- The action is recorded in the audit log (`scim.user.deactivated` /
  `scim.user.deleted`), giving you a timestamped record for termination
  evidence (CC6.8).

If the person is later re-added in the IdP, the same SCIM resource is
reactivated (`active: true`): the account comes back, any lockout state is
cleared, but **MFA is not restored** — they will re-enroll TOTP the next
time they sign in.

## Troubleshooting

- **IdP reports "connection test failed."** Confirm `--scim-enable` is set,
  the server is reachable over HTTPS at the configured base URL, and the
  bearer token in the IdP matches `--scim-token` exactly (whitespace/newline
  differences are a common copy-paste mistake).
- **Every request returns 401.** The bearer token is checked on every
  `/scim/v2/*` call including the discovery endpoints — there's no
  unauthenticated preview. Re-verify the token value configured in the IdP.
- **A user I expected to be deactivated is still active.** Confirm that
  user's account was originally created by SCIM (check `provisioning_source`
  via an admin) — a locally-created account is not reachable by SCIM
  deactivation by design; disable it from the dashboard instead.

## See also

- `docs/auth-architecture.md` "SCIM v2 provisioning" — full technical
  reference (endpoint list, provenance-guard design, storage decision, audit
  actions).
- [REST API Reference](rest-api.md#scim-v2-provisioning) — endpoint-by-endpoint
  wire reference.
- [Authentication](authentication.md) — OIDC/SAML SSO setup (SCIM
  provisions the account; SSO is how the account signs in).
