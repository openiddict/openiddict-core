# OpenIddict vs Duende IdentityServer — feature gap report

| | |
|---|---|
| Date | 2026-09-13 |
| OpenIddict baseline | 8.0.0-preview.5 (`dd0d5d7d`, identical to upstream `dev`) |
| Fork state | Linear stack on `dev`, not pushed: `docs/duende-parity-plan` → `feature/jar` → `feature/ciba` → `feature/ciba-client` → `feature/key-management` → `feature/dpop` → `feature/jwt-introspection` → `feature/dynamic-providers` → `feature/bff` → `feature/templates-admin-api` → `feature/saml` |
| Duende reference | IdentityServer 8.0.7 (June 2026) |
| Detailed plan | [`docs/plans/duende-parity-plan.md`](../plans/duende-parity-plan.md) |

Legend: ✅ available · 🟢 implemented in this fork (not upstream) · ⚠️ partial · ❌ missing · ⏸ deferred to upstream · ⛔ dropped

## 1. Summary

- **Protocol core is already at parity:** authorization code + PKCE, client credentials, refresh, device flow, token exchange, PAR, mTLS (client auth + bound tokens), `private_key_jwt`, introspection, revocation, resource indicators, `iss` response parameter.
- **Closed in this fork:** JAR (server + client), CIBA poll mode (server + client), automatic key management, DPoP (server + validation + client), JWT introspection responses (server + client + validation), dynamic providers, BFF, templates, admin API, SAML 2.0 IdP (MVP).
- **Largest remaining gaps:** logout and sessions (back-channel logout, session management, SAML SLO) and dynamic client registration.
- **Upstream is working on two of them:** back-channel logout (#2175) and DCR (#2404) are milestoned for `8.0.0-preview.5`, so the fork waits.

## 2. Gap matrix

| Feature | Duende 8 | OpenIddict | Status / next step |
|---|---|---|---|
| Code+PKCE, CC, refresh, device, token exchange, PAR, mTLS | ✅ | ✅ | — |
| JWT-secured authorization requests (RFC 9101), by value | ✅ | 🟢 | Done (`d5c9bff7`) |
| JAR by reference (external `request_uri`) | ✅ (opt-in) | ❌ | Not planned (SSRF risk) |
| CIBA — poll mode | ✅ | 🟢 server + client | Done (`bbd52cbf`, `b67cf1f3`) |
| CIBA — signed requests, ping/push | ❌ ping/push | ❌ | Low priority |
| Server-side sessions | ✅ (expiry, query/terminate API) | ⚠️ entity + validation only | ⏸ P1 / P11.1 after upstream |
| Back-channel logout | ✅ | ❌ | ⏸ P2 (upstream #2175) |
| Front-channel logout | ✅ | ❌ | ⛔ declined upstream (third-party cookies) |
| OIDC Session Management (`check_session_iframe`) | ✅ | ❌ | ⛔ same reason |
| RP-side logout in client stack | n/a | ❌ | ⏸ P4 |
| DPoP (RFC 9449, incl. nonces) | ✅ | 🟢 server + validation + client | Done (P5) |
| JARM (`response_mode=jwt`) | ❌ | ❌ | ⛔ not parity |
| JWT introspection response (RFC 9701) | ✅ | 🟢 server + client + validation | Done (P12) |
| Dynamic client registration (RFC 7591) | ✅ (Configuration API) | ❌ | ⏸ P9 (upstream #2404) |
| DCR management (RFC 7592) | ❌ | ❌ | Included in P9 |
| Automatic key management | ✅ signing keys (90 d rotate / 14 d announce / 14 d retain) | 🟢 signing + encryption | Done (P10) |
| Dynamic external providers (OIDC/SAML) | ✅ | 🟢 OIDC via `IOpenIddictClientRegistrationProvider` (no store entity) | Done (P11.2); SAML SP side not planned |
| BFF | ✅ Duende.BFF 4.2 | 🟢 `OpenIddict.Client.AspNetCore.Bff` (refresh, token handlers, YARP, session endpoints, back-channel logout) | Done (P11.3) |
| UI templates | ✅ | 🟢 `OpenIddict.Templates` (Identity server, empty server, BFF) | Done (P11.4) |
| Admin UI | ❌ (third-party) | 🟡 admin API only (`MapOpenIddictAdminApi`), no UI | Done (P11.5, API only) |
| SAML 2.0 IdP | ✅ built-in (v8) | 🟢 `OpenIddict.Server.Saml` + `.AspNetCore` + `.Owin` (metadata, SP-initiated SSO Redirect/POST, signed assertions, IdP-initiated opt-in); no SLO | Done (P11.6 MVP); SLO after P1 |
| FAPI 2.0 conformance report | ✅ | ❌ | Prerequisites done (DPoP, key management); conformance run pending |
| Multi-issuer hosting | ✅ add-on | ❌ | Not planned |

## 3. OpenIddict strengths with no Duende equivalent

| Area | OpenIddict |
|---|---|
| Client stack | Full OAuth/OIDC client, including desktop/mobile integration and 100+ generated web providers |
| Hosts | ASP.NET Core **and** OWIN / .NET Framework |
| Stores | EF Core, EF6, MongoDB (incl. keys); Quartz pruning job |
| Licensing | Apache 2.0, no paid tiers |

## 4. Implemented in this fork

| Phase | Commit | What changed | Notable behaviour |
|---|---|---|---|
| P6 JAR | `d5c9bff7` | Server: `EnableRequestObjectSupport()`, `RequireSignedRequestObjects()`, per-client `ft:jar`, discovery metadata. Client: `UseSignedRequestObjects`. | Parameters outside the object are ignored (RFC 9101). Objects are validated with the client JWKS. |
| P8 CIBA (server) | `bbd52cbf` | Backchannel endpoint and pass-through, `urn:openid:params:grant-type:ciba`, `OpenIddictServerService` (list / approve / reject), discovery metadata. | Requires `SetIssuer`, token storage and non-degraded mode. **Device flow now returns `interval` and enforces `slow_down`**; disable with `SetPollingInterval(null)`. |
| P8b CIBA (client) | `b67cf1f3` | `AllowClientInitiatedBackchannelAuthenticationFlow()`, `OpenIddictClientService.ChallengeUsingBackchannelAsync` / `AuthenticateWithBackchannelAsync`, discovery extraction. | Poll mode only. PAR requirement now enforced only for interactive flows. |
| P5 DPoP | `0dae3a9d` `0a732595` `dbc144f5` | Server: `EnableDPoPSupport()`, `RequireDPoP()`, `RequireDPoPNonces()`, per-client `ft:dpop`, `dpop_jkt`, discovery `dpop_signing_alg_values_supported`. Validation: `DPoP` scheme, optional `IDistributedCache` replay cache. Client: `EnableDPoPTokenBinding()`, `DPoPSigningCredentials`, `CreateDPoPProofAsync`. | Opt-in. `cnf.jkt` on access tokens and public-client refresh tokens; `token_type=DPoP`. Server replay check writes one token entry per proof (token storage only). |
| P12 JWT introspection | `f1ff44d8` `811b913a` `a2c44c5a` `0152298e` `f1a9a312` | Server: `EnableJsonWebTokenIntrospectionResponses()`, `application/token-introspection+jwt` in ASP.NET Core/OWIN, discovery `introspection_signing_alg_values_supported` / `introspection_encryption_*`. Client: `OpenIddictClientRegistration.RequireJsonWebTokenIntrospectionResponses`. Validation: `RequireJsonWebTokenIntrospectionResponses()`. | Opt-in. Errors, anonymous and public clients get JSON. Encrypted only if the application sets `intr_rsp:enc_alg` (`RSA-OAEP`) and its JWKS has an RSA `enc` key. |
| P11.2 dynamic providers | `ad43bd3a` `5315d310` | Client: `IOpenIddictClientRegistrationProvider`, `AddRegistrationProvider<T>()`, `SetDynamicRegistrationCacheLifetime()`; all registration lookups go through the providers. ASP.NET Core: decorated `IAuthenticationSchemeProvider`. OWIN: dynamic forwarded authentication types. | No persistence entity (custom providers). Dynamic registrations must use redirect URIs declared in options; cached by id (30 min default). |
| P11.3 BFF | `6e1aca1f` `36a6a9b2` | New package `OpenIddict.Client.AspNetCore.Bff` (YARP 2.3.0): `UseBff()`, cookie auto-refresh, `MapOpenIddictBffEndpoints()` (login, logout, user, callbacks, back-channel logout), `UseOpenIddictBff()` antiforgery middleware, `AddOpenIddictBff*AccessTokenHandler()`, `AddOpenIddictBffTransforms()`, `IOpenIddictClientAspNetCoreBffSessionStore`. Client hosts store `backchannel_access_token_type`. | `UseBff()` enables redirection/post-logout passthrough and adds `/bff/callback/*` URIs. Refresh single-flight and replay caches are in-memory (per instance). Back-channel logout removes sessions only with a BFF-aware ticket store. |
| P11.4 templates | `56cd9786` | New template pack `templates/OpenIddict.Templates.csproj`: `openiddict-server-identity` (Identity UI + EF Core, MVC authorization/device/end session/userinfo), `openiddict-server-empty` (minimal APIs, pass-through), `openiddict-bff` (client + BFF + YARP). `templates/verify.sh`. | Default OpenIddict version checked at pack time. Empty server login is a development-only placeholder. |
| P11.5 admin API | `e4cc3771` `6a0d72b7` | `Server.AspNetCore`: `MapOpenIddictAdminApi(policy, prefix)` — applications/scopes CRUD, authorizations (list/get/create/delete/revoke), tokens (list/get/delete/revoke), keys (list/get/revoke). | Policy required; JSON content type required for POST/PATCH; secrets, token payloads, key material and private JWK parameters never returned; authorization revoke cascades to tokens. No UI. |
| P11.6 SAML IdP | `b6ba3f30` `814f25f8` `3c25b4d4` | New packages `OpenIddict.Server.Saml` (net48 + net10.0): `UseSaml()`, `OpenIddictServerSamlService`, `IOpenIddictServerSamlServiceProviderStore`, `IOpenIddictServerSamlAssertionProvider`; `OpenIddict.Server.Saml.AspNetCore`: `UseAspNetCore()`, `MapOpenIddictSamlEndpoints()` (`/saml/metadata`, `/saml/sso`); `OpenIddict.Server.Saml.Owin`: `UseOwin()`, `app.UseOpenIddictSaml()`. | Signed AuthnRequests required by default; single root signature, RSA-SHA2 only, no DTD; ACS allow-list; challenge/callback with a data-protected state (full AuthnRequest, SP/ACS re-checked); OWIN requires `SetAuthenticationType()`; no SLO/encryption/artifact binding. |
| P10 automatic key management | `4d19d539` | New **Key** entity (EF Core `OpenIddictKeys` table, EF6, MongoDB `openiddict.keys`), `IOpenIddictKeyManager`. Server: `EnableAutomaticKeyManagement()`, `OpenIddictServerKeyRing`, `IOpenIddictServerKeyProtector` (in `OpenIddict.Server`; Data Protection implementation via `UseDataProtection()`). Local validation follows rotation. Quartz: `EnableKeyPruning()`. | Schema change for every EF user. Static keys still used, after the active auto key. `UseDataProtection()` also switches token formats unless `PreferDefaultTokenFormat()`. |

Latest runs, all green (P12 suites from `0152298e`, MongoDB/Quartz/EF/core from `4d19d539`): server unit 706 · ASP.NET Core integration 1,586 · OWIN integration 1,556 · core 661 · client 196 · abstractions 1,451 · MongoDB 36 · Quartz 34 · validation 118 · validation ASP.NET Core / OWIN integration 30 / 30 · EF Core 10 · EF6 7 · Data Protection 1. P11.3 (`feature/bff`): BFF 60 · client 219 · client ASP.NET Core / OWIN integration 3 / 5 · abstractions 1,451. P11.4/P11.5 (`feature/templates-admin-api`): ASP.NET Core integration 1,620 (30 admin API) · OWIN integration 1,560 · abstractions 1,451 · `templates/verify.sh` 3 builds + 16 smoke checks. P11.6 (`feature/saml`): SAML 57 × 2 (net10.0, net48) · SAML ASP.NET Core 14 · SAML OWIN 11 · abstractions 1,451.

## 5. Remaining work (ordered)

| # | Phase | Size | Dependency / risk |
|---|---|---|---|
| 3 | P11.6 follow-ups (SLO, encrypted assertions) | L | SLO needs P1 |
| — | P1, P2, P4, P9, P11.1 | L | Blocked until upstream `8.0.0-preview.5` is merged |

## 6. Risks

- **Divergence from upstream:** keep fork-only features isolated per branch; rebase when preview.5 ships.
- **Schema changes** (sessions, keys, provider registrations): batch them into one preview.
- **Behaviour changes** needing release notes: device-flow `interval`/`slow_down`; PAR requirement limited to interactive flows; `OpenIddictKeys` table appears in EF migrations even when key management is off; client `IAuthenticationSchemeProvider` is decorated by `UseAspNetCore()`.
- **Key management:** losing the Data Protection key ring makes stored keys unreadable (they are skipped, new ones are created); concurrent first start on several instances can create extra keys (all published, same active key chosen).
- **Scope:** every phase is independently shippable, and P11.4–P11.6 can be dropped.
