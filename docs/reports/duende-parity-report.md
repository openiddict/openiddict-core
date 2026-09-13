# OpenIddict vs Duende IdentityServer — feature gap report

| | |
|---|---|
| Date | 2026-09-14 |
| OpenIddict baseline | 8.0.0-preview.5 (`dd0d5d7d` = `origin/dev`) |
| Fork state | All phases merged into local `dev`, 46 commits ahead of `origin/dev`, not pushed; last implementation commit `3c25b4d4` |
| Duende reference | IdentityServer 8.0.7 (June 2026) |
| Detailed plan | [`docs/plans/duende-parity-plan.md`](../plans/duende-parity-plan.md) |

Legend: ✅ available · 🟢 implemented in this fork (not upstream) · ⚠️ partial · ❌ missing · ⏸ deferred to upstream · ⛔ dropped

## 1. Summary

- **Protocol core was already at parity:** authorization code + PKCE, client credentials, refresh, device flow, token exchange, PAR, mTLS (client auth + bound tokens), `private_key_jwt`, introspection, revocation, resource indicators, `iss` response parameter.
- **Closed in this fork (11 phases, all reviewed):** JAR, CIBA poll mode, automatic key management, DPoP, JWT introspection responses, dynamic providers, BFF, templates, admin API, SAML 2.0 IdP (MVP, ASP.NET Core + OWIN).
- **Every phase not blocked on upstream is done.** Last test runs had 0 failures (§4.1).
- **Largest remaining gaps:** logout and sessions (back-channel logout, session management, SAML SLO) and dynamic client registration. No server-side `backchannel_logout`/`registration_endpoint` support exists in `src/`.
- **Upstream owns two of them:** back-channel logout (#2175) and DCR (#2404), so the fork waits.

## 2. Gap matrix

| Feature | Duende 8 | OpenIddict | Status / next step |
|---|---|---|---|
| Code+PKCE, CC, refresh, device, token exchange, PAR, mTLS | ✅ | ✅ | — |
| JAR (RFC 9101), by value | ✅ | 🟢 server + client | Done (P6) |
| JAR by reference (external `request_uri`) | ✅ (opt-in) | ❌ | Not planned (SSRF risk) |
| CIBA — poll mode | ✅ | 🟢 server + client | Done (P8, P8b) |
| CIBA — ping/push | ❌ | ❌ | Low priority |
| Server-side sessions | ✅ (expiry, query/terminate API) | ⚠️ entity + validation only (upstream) | ⏸ P1 / P11.1 |
| Back-channel logout (OP) | ✅ | ❌ | ⏸ P2 (upstream #2175) |
| Front-channel logout / `check_session_iframe` | ✅ | ❌ | ⛔ declined upstream (third-party cookies) |
| RP-side logout in client stack | n/a | ❌ (BFF only) | ⏸ P4 |
| DPoP (RFC 9449, incl. nonces) | ✅ | 🟢 server + validation + client | Done (P5) |
| JARM (`response_mode=jwt`) | ❌ | ❌ | ⛔ not parity |
| JWT introspection response (RFC 9701) | ✅ | 🟢 server + client + validation | Done (P12) |
| Dynamic client registration (RFC 7591 / 7592) | ✅ 7591 only | ❌ | ⏸ P9 (upstream #2404) |
| Automatic key management | ✅ signing only | 🟢 signing + encryption | Done (P10) |
| Dynamic external providers | ✅ OIDC + SAML | 🟢 OIDC via registration providers (no store entity) | Done (P11.2); SAML SP not planned |
| BFF | ✅ Duende.BFF 4.2 | 🟢 `OpenIddict.Client.AspNetCore.Bff` | Done (P11.3) |
| UI templates | ✅ | 🟢 `OpenIddict.Templates` (3 templates) | Done (P11.4) |
| Admin UI | ❌ (third-party) | ⚠️ admin API only | Done (P11.5, no UI) |
| SAML 2.0 IdP | ✅ built-in | 🟢 `OpenIddict.Server.Saml` + `.AspNetCore` + `.Owin`; no SLO | Done (P11.6 MVP) |
| FAPI 2.0 conformance report | ✅ | ❌ | Prerequisites done; run pending |
| Multi-issuer hosting | ✅ add-on | ❌ | Not planned |

## 3. OpenIddict strengths with no Duende equivalent

| Area | OpenIddict |
|---|---|
| Client stack | Full OAuth/OIDC client, desktop/mobile integration, 100+ generated web providers |
| Hosts | ASP.NET Core **and** OWIN / .NET Framework (incl. SAML IdP) |
| Stores | EF Core, EF6, MongoDB (incl. keys); Quartz pruning (incl. keys) |
| Licensing | Apache 2.0, no paid tiers |

## 4. Implemented in this fork

| Phase | Commits | Public surface | Notable behaviour |
|---|---|---|---|
| P6 JAR | `d5c9bff7` | Server: `EnableRequestObjectSupport()`, `RequireSignedRequestObjects()`, per-client `ft:jar`, discovery. Client: `OpenIddictClientRegistration.UseSignedRequestObjects`. | Parameters outside the object ignored; object validated with the client JWKS. |
| P8 CIBA server | `bbd52cbf` | Backchannel endpoint + pass-through, `urn:openid:params:grant-type:ciba`, `OpenIddictServerService` (list/approve/reject), discovery. | Needs `SetIssuer`, token storage, non-degraded mode. **Device flow now returns `interval` and enforces `slow_down`** (`SetPollingInterval(null)` disables). |
| P8b CIBA client | `b67cf1f3` | `AllowClientInitiatedBackchannelAuthenticationFlow()`, `ChallengeUsingBackchannelAsync`, `AuthenticateWithBackchannelAsync`. | Poll only. PAR requirement enforced only for interactive flows. |
| P10 key management | `4d19d539` | **Key** entity (EF Core `OpenIddictKeys`, EF6, MongoDB `openiddict.keys`), `IOpenIddictKeyManager`, `EnableAutomaticKeyManagement()`, `OpenIddictServerKeyRing`, `IOpenIddictServerKeyProtector` (Data Protection impl via `UseDataProtection()`), Quartz `EnableKeyPruning()`. | Schema change for EF users. Static keys used after the active auto key. Local validation follows rotation. `UseDataProtection()` also switches token formats unless `PreferDefaultTokenFormat()`. |
| P5 DPoP | `0dae3a9d` `0a732595` `dbc144f5` `27de4821` `19d36ea3` | Server: `EnableDPoPSupport()`, `RequireDPoP()`, `RequireDPoPNonces()`, `ft:dpop`, `dpop_jkt`, discovery. Validation: `DPoP` scheme, optional `IDistributedCache` replay cache. Client: `EnableDPoPTokenBinding()`, `CreateDPoPProofAsync`. | Opt-in. `cnf.jkt` on access and public-client refresh tokens. Server replay check = one token entry per proof. `x5c`/`x5u` ignored; `alg` must match `kty`/`crv`. No PAR proof when mTLS binding can be negotiated. |
| P12 JWT introspection | `f1ff44d8` `811b913a` `a2c44c5a` `9d913f9a` `0152298e` `f1a9a312` | Server: `EnableJsonWebTokenIntrospectionResponses()`, `application/token-introspection+jwt` (ASP.NET Core/OWIN), discovery. Client: `OpenIddictClientRegistration.RequireJsonWebTokenIntrospectionResponses`. Validation: `RequireJsonWebTokenIntrospectionResponses()`. | Opt-in. Errors/anonymous/public clients get JSON. Encrypted only with `intr_rsp:enc_alg` (`RSA-OAEP`; `enc` default `A128CBC-HS256`); misconfiguration → ID0552/ID0553. |
| P11.2 dynamic providers | `ad43bd3a` `5315d310` `776c7ca1` | `IOpenIddictClientRegistrationProvider`, `AddRegistrationProvider<T>()`, `SetDynamicRegistrationCacheLifetime()`. ASP.NET Core: decorated `IAuthenticationSchemeProvider`; OWIN: dynamic authentication types. | No store entity. Redirect URIs must be declared in options. Cached by id (30 min); replaced when issuer/provider name/client id change. |
| P11.3 BFF | `6e1aca1f` `36a6a9b2` | `OpenIddict.Client.AspNetCore.Bff` (YARP 2.3.0): `UseBff()`, `MapOpenIddictBffEndpoints()` (login, logout, user, callbacks, back-channel logout), `UseOpenIddictBff()`, `AddOpenIddictBff{User,Client}AccessTokenHandler()`, `AddOpenIddictBffTransforms()`, `IOpenIddictClientAspNetCoreBffSessionStore`. | Cookie auto-refresh. `UseBff()` adds `/bff/callback/*` and passthroughs. Single-flight/replay caches in-memory. Antiforgery fail-closed in API endpoints and YARP. Logout tokens without `exp` need a recent `iat`. |
| P11.4 templates | `56cd9786` `1cb254e1` | `templates/OpenIddict.Templates.csproj`: `openiddict-server-identity`, `openiddict-server-empty`, `openiddict-bff`; `templates/verify.sh`. | OpenIddict version checked at pack. Empty-server login is dev-only; `prompt=none` without login → `login_required`. Bootstrap pinned with SRI. |
| P11.5 admin API | `e4cc3771` `6a0d72b7` | `MapOpenIddictAdminApi(policy, prefix)`: applications/scopes CRUD; authorizations list/get/create/delete/revoke; tokens list/get/delete/revoke; keys list/get/revoke. | Policy required; JSON body required for POST/PATCH; secrets, payloads, key material, private JWK parameters never returned; authorization revoke cascades. |
| P11.6 SAML IdP | `b6ba3f30` `814f25f8` `3c25b4d4` | `OpenIddict.Server.Saml` (net48 + net10.0): `UseSaml()`, `OpenIddictServerSamlService`, `IOpenIddictServerSamlServiceProviderStore`, `IOpenIddictServerSamlAssertionProvider`. `.AspNetCore`: `MapOpenIddictSamlEndpoints()` (`/saml/metadata`, `/saml/sso`). `.Owin`: `UseOwin()`, `app.UseOpenIddictSaml()`. | Signed AuthnRequests required by default; single root signature, RSA-SHA2, no DTD; ACS allow-list; data-protected state (SP/ACS re-checked); OWIN requires `SetAuthenticationType()`; timezone-less `IssueInstant` = UTC; no SLO/encryption/artifact binding. |

### 4.1 Latest test runs (0 failures)

Counts come from the last run of each suite, at the commit shown. None were re-run after the merge into `dev`. ASP.NET Core suites ran on net10.0, OWIN on net48.

| Suite | Passed | Run at |
|---|---|---|
| Server unit | 706 | `f1a9a312` |
| Server ASP.NET Core / OWIN integration | 1,620 (30 admin API) / 1,560 | `1cb254e1` |
| Core · MongoDB · Quartz · EF Core · EF6 · Data Protection | 661 · 36 · 34 · 10 · 7 · 1 | `4d19d539` |
| Abstractions | 1,451 | `3c25b4d4` |
| Validation unit (net10.0 / net48) · ASP.NET Core / OWIN | 120 / 120 · 30 / 30 | `f1a9a312` |
| Client unit (net10.0 / net48) | 219 / 219 | `776c7ca1` |
| Client ASP.NET Core / OWIN integration · BFF | 3 / 5 · 60 | `36a6a9b2` |
| `templates/verify.sh` | 3 builds + 16 smoke checks | `1cb254e1` |
| SAML (net10.0 / net48) · ASP.NET Core · OWIN | 57 / 57 · 14 · 11 | `3c25b4d4` |

## 5. Remaining work (ordered)

| # | Work | Size | Dependency / risk |
|---|---|---|---|
| 0 | Full test pass on merged `dev` | S | Before push |
| 1 | P1 sessions, P2 back-channel logout, P4 client RP logout, P9 DCR, P11.1 session admin | L | ⏸ upstream #2175, #2404 |
| 2 | SAML: SLO, encrypted assertions, artifact binding, AuthnRequest replay cache | L | SLO needs P1 |
| 3 | Review follow-ups: DPoP nonce retry with fresh `client_assertion`; `DPoP` in userinfo challenge; distributed BFF caches; JWE BFF logout tokens; JWT introspection `alg` restriction | S–M | Independent |
| 4 | FAPI 2.0 conformance run; end-to-end client ↔ server tests (DPoP, JWT introspection) | M | Conformance environment |

## 6. Risks

- **Divergence from upstream:** 46 fork-only commits on `dev`; rebase on each upstream preview.
- **Schema changes** (keys now; sessions, registrations later): ship in one preview.
- **Behaviour changes needing release notes:**

| Area | Change |
|---|---|
| Device flow / PAR | `interval`/`slow_down` returned/enforced; PAR requirement limited to interactive flows |
| EF | `OpenIddictKeys` table in migrations even with key management off |
| Client ASP.NET Core | `IAuthenticationSchemeProvider` decorated by `UseAspNetCore()` (replacing it later disables dynamic schemes) |
| DPoP | `x5c`/`x5u`-only or `alg`/`kty` mismatched proofs rejected; no PAR proof when mTLS binding negotiable |
| JWT introspection | Encryption only on `intr_rsp:enc_alg`; exception instead of plaintext on misconfiguration |
| Dynamic providers | Cached registration replaced when issuer/provider name/client id change |
| BFF | 401 without antiforgery header even without `UseOpenIddictBff()`; `User` routes not proxied without a token; stale/future `iat` logout tokens rejected; malformed → 400 |
| Admin API | Private/symmetric JWK values stripped (PATCH echoing them stores stripped set); authorization revoke cascades |
| SAML | Callback state rejected (400) if SP/ACS/issuer/signature/IdP-initiated settings changed; per-SP `AssertionLifetime` ≤ 0 invalid |

- **Security residuals:**
  - DPoP replay race on EF6 (no unique `ReferenceId`) and MongoDB (user-created index).
  - In-memory BFF caches break rolling refresh tokens without sticky sessions.
  - SAML request state reusable until expiry (1 h, not session-bound).
  - IdP-initiated SSO (opt-in) carries login-CSRF risk.
  - SAML metadata `WantAuthnRequestsSigned` ignores custom stores.
  - SAML `Destination` check needs forwarded headers behind proxies.
- **Key management:** lost Data Protection key ring → stored keys skipped, new ones created; concurrent first start can create extra keys (all published, same active key).
- **Scope:** every phase is independently shippable; P11.4–P11.6 can be dropped.
