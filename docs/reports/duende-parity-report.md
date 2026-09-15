# OpenIddict vs Duende IdentityServer — feature gap report

| | |
|---|---|
| Date | 2026-09-15 |
| OpenIddict baseline | 8.0.0-preview.5 (`dd0d5d7d` = `origin/dev`) |
| Fork state | All phases and follow-ups merged into local `dev`, not pushed; tip `fe9e453e` |
| Duende reference | IdentityServer 8.0.7 (June 2026) |
| Detailed plan | [`docs/plans/duende-parity-plan.md`](../plans/duende-parity-plan.md) |

Legend: ✅ available · 🟢 implemented in this fork (not upstream) · ⚠️ partial · ❌ missing · ⛔ dropped

## 1. Summary

- **Protocol core was already at parity:** authorization code + PKCE, client credentials, refresh, device flow, token exchange, PAR, mTLS, `private_key_jwt`, introspection, revocation, resource indicators, `iss`.
- **Round 1 (11 phases):** JAR by value, CIBA poll, automatic key management, DPoP, JWT introspection, dynamic providers, BFF, templates, admin API, SAML IdP MVP.
- **Round 2 (12 workstreams, this report):** server sessions + back/front-channel logout + session management, client RP logout, DCR (RFC 7591/7592), CIBA ping/push, JARM, JAR by reference, multi-issuer hosting, FAPI 2.0 profile + review follow-ups, SAML encryption/artifact/replay cache, SAML SP (client stack), SAML SLO, admin UI (incl. sessions).
- **No Duende feature is missing any more.** Open items are depth (durable delivery, background expiry), interop/conformance runs and environment-bound verification (§5).
- **Upstream decisions overridden:** back-channel logout (#2175) and DCR (#2404) were implemented fork-side instead of waiting; front-channel logout and JARM (dropped in round 1) were implemented on request.

## 2. Gap matrix

| Feature | Duende 8 | OpenIddict fork | Status |
|---|---|---|---|
| Code+PKCE, CC, refresh, device, token exchange, PAR, mTLS | ✅ | ✅ | — |
| JAR by value | ✅ | 🟢 server + client | Done (P6) |
| JAR by reference (external `request_uri`) | ✅ opt-in | 🟢 server, SSRF-filtered fetcher | Done (P13) |
| CIBA poll | ✅ | 🟢 server + client | Done (P8) |
| CIBA ping / push | ❌ | 🟢 server + client, signed CIBA requests | Done (P8c); no built-in RP notification endpoint |
| Server-side sessions (expiry, query, terminate) | ✅ | 🟢 store/manager + server + admin API/UI | Done (P1, P11.1) |
| Back-channel logout (OP) | ✅ | 🟢 | Done (P2) |
| Front-channel logout / `check_session_iframe` | ✅ | 🟢 | Done (P3) |
| RP-side logout in client stack | n/a | 🟢 ASP.NET Core + OWIN + BFF | Done (P4) |
| DPoP | ✅ | 🟢 server + validation + client | Done (P5) |
| JARM | ❌ | 🟢 server + client (sign + RSA-OAEP encrypt) | Done (P7) |
| JWT introspection response (RFC 9701) | ✅ | 🟢 + alg restriction | Done (P12, P15) |
| Dynamic client registration | ✅ 7591 | 🟢 7591 + 7592, server + client | Done (P9); no `jwks_uri` |
| Automatic key management | ✅ signing | 🟢 signing + encryption | Done (P10) |
| Dynamic external providers | ✅ OIDC + SAML | 🟢 OIDC + SAML SP | Done (P11.2, P17) |
| BFF | ✅ | 🟢 + distributed caches | Done (P11.3, P15) |
| UI templates | ✅ | 🟢 3 templates, `--admin-ui` | Done (P11.4) |
| Admin UI | ❌ (third-party) | 🟢 API + Blazor SSR UI (incl. sessions) | Done (P11.5, P18) |
| SAML 2.0 IdP | ✅ | 🟢 SSO, encryption, artifact, replay cache, SLO (Redirect/POST/SOAP) | Done (P11.6, P16, P19) |
| SAML 2.0 SP | ✅ (dynamic providers) | 🟢 `OpenIddict.Client.Saml` (+ AspNetCore/Owin) | Done (P17); ACS POST only, no SLO |
| FAPI 2.0 security / message signing profile | ✅ conformance report | 🟢 server + client presets | Done (P15); conformance run pending |
| Multi-issuer hosting | ✅ add-on | 🟢 per-request issuer + credentials | Done (P14); not with CIBA/mTLS aliases |

## 3. OpenIddict strengths with no Duende equivalent

| Area | OpenIddict |
|---|---|
| Client stack | Full OAuth/OIDC client (+ SAML SP), desktop/mobile integration, 100+ web providers |
| Hosts | ASP.NET Core **and** OWIN / .NET Framework (SAML IdP/SP, RP logout, DCR) |
| Stores | EF Core, EF6, MongoDB (incl. keys, sessions); Quartz pruning |
| Protocols beyond Duende | JARM, CIBA ping/push, RFC 7592 management, SAML SOAP SLO |
| Licensing | Apache 2.0 |

## 4. Implemented in this fork

Round 1 (unchanged, see previous revision of this report / plan Progress): P6 JAR `d5c9bff7` · P8 CIBA poll `bbd52cbf` `b67cf1f3` · P10 keys `4d19d539` · P5 DPoP `0dae3a9d`…`19d36ea3` · P12 JWT introspection `f1ff44d8`…`f1a9a312` · P11.2 dynamic providers `ad43bd3a`…`776c7ca1` · P11.3 BFF `6e1aca1f` `36a6a9b2` · P11.4 templates `56cd9786` `1cb254e1` · P11.5 admin API `e4cc3771` `6a0d72b7` · P11.6 SAML IdP `b6ba3f30` `814f25f8` `3c25b4d4`.

Round 2:

| Phase | Commits | Public surface | Notable behaviour |
|---|---|---|---|
| P1/P2/P3 sessions + OP logout | `cf7dd70d` `ee4ae5f1` `cc13f47b` `9d7bae60` | Store/manager `GetExpirationDateAsync`, `TryExtendAsync`, `TryRevokeAsync`, `RevokeBySessionIdAsync`; session `ExpirationDate`/`LastActivityDate`. Builder `EnableBackchannelLogout/EnableFrontchannelLogout/EnableSessionManagement/SetCheckSessionIframeEndpointUris/EnableSessionRevocationOnSignOut/SetSessionIdleTimeout/SetSessionLifetime/EnableAutomaticSessionCreation/EnableIdentityTokenHintSessionResolution`. `OpenIddictServerService.TerminateSessionAsync`/`GetFrontchannelLogoutUrisAsync`. `OpenIddict.Server.SystemNetHttp`. Admin API sessions. | Opt-in. Session from host `Properties.SessionId` (`id_token_hint` sid only when opted in). Expired/revoked session → sign-in rejected (ID2363). Re-termination of revoked session sends nothing. Browser state cookie random + separate HttpOnly binding cookie. `frontchannel_logout_uri` must share origin with a redirect URI (ID2364). Iframe checks `e.origin`. |
| P4 client RP logout | `2833482b`…`53277c89` `d1820d4d` | Client `SetBackchannelLogoutEndpointUris`, `SetFrontchannelLogoutEndpointUris`, `SetLogoutTokenMaximumAge`, `AddSessionStore`, `DisableFrontchannelLogoutSessionVerification`, `DisableLogoutTokenExpirationRequirement`; `IOpenIddictClientSessionStore`; `AuthenticateWithLogoutTokenAsync`; host passthroughs + sign-out scheme. | Logout token fully validated (sig, iss/aud, typ, events, no nonce, sub/sid, `exp` required, `jti` replay in-memory + optional `IDistributedCache`). Failures → 400 JSON. Startup validation ID0760/ID0766. Front-channel only removes the verified current session. BFF delegates to it. |
| P9 DCR | `ebe69efc`…`966d50eb` `030c4e35` | Server `SetRegistrationEndpointUris`, `EnableDynamicClientRegistration`, `AllowAnonymousClientRegistration`, `SetInitialAccessTokenScopes`, `SetRegistrationAccessTokenLifetime`, `RequireSoftwareStatement`, `AddSoftwareStatementSigningKey`, `SetRegistrationAllowedGrantTypes/Scopes`. Client `RegisterAsync`/`Get/Update/DeleteRegistrationAsync`. | Opt-in. Unsafe URI schemes rejected; implicit web clients need https non-loopback. Grant/scope allow-lists (password/token exchange not registrable by default). Registration access token revoked atomically before GET/PUT. Tokens only from `Authorization` header. `software_statement` echoed. |
| P8c CIBA ping/push | `b07d681e`…`4ea80d79` | Server `AllowBackchannelPing/PushTokenDeliveryMode`, `EnableSignedBackchannelAuthenticationRequestSupport`, `EnableBackchannelUserCodeParameterSupport`, `SetBackchannelNotificationRetryPolicy`; `SendBackchannelNotificationContext`. Client `BackchannelChallengeRequest.TokenDeliveryMode/ClientNotificationToken/UserCode`, `AuthenticateWithBackchannelNotificationAsync`, `ReadBackchannelNotificationAsync()` (ASP.NET Core/OWIN). | Client registration `bca:dlv_mode` always resolved; mode not enabled → `unauthorized_client`. Push clients cannot poll. `client_notification_token` must be b64token. Push rejects DPoP/cert-bound clients. Pushed tokens go through the token response pipeline. Notifications inline with retries. |
| P7 JARM | `4008a5b9`…`33ce5dcd` | Server `EnableJwtSecuredAuthorizationResponses`, `RequireJwtSecuredAuthorizationResponses`, `SetAuthorizationResponseLifetime`; settings `auth_rsp:*`. Client registration `RequireJwtSecuredAuthorizationResponses`, `AuthorizationResponseSigningAlgorithm`, `RequireEncryptedAuthorizationResponses`. | All params (errors too) in one JWT (`iss`, `aud`, `exp`), JWA `alg`, optional RSA-OAEP. Generated at order 249_000. Require mode → discovery lists only `*.jwt`. Client validates sig/iss/aud/exp/state; RS256 default when nothing advertised. State tokens carry `oi_rsp_mode`. |
| P13/P14 JAR by reference + multi-issuer | `bff94117` `78b31cf2` `760c6009` `6c6fab8a` | `EnableRequestObjectReferenceSupport`, `DisableRequestUriRegistrationRequirement`, `IOpenIddictServerRequestObjectFetcher`, `UseSystemNetHttp()` fetcher options (`SetRemoteAddressFilter`, size/timeout/cache). `EnableIssuerResolution`, `AddIssuers`, `SetIssuerResolver<T>`, `SetIssuerCredentialsProvider<T>`. | Opt-in. `request_uri` must match registered prefix (`req_obj:req_uris`), non-public addresses blocked (connect-time on .NET), fragment hash checked. PAR requirement also blocks external `request_uri` (ID2466). Issuer resolution: token `iss` validated per issuer, per-issuer keys; startup error without issuers/resolver (ID0929); incompatible with CIBA/mTLS aliases (ID0927). |
| P15 FAPI 2.0 + follow-ups | `db53d7f8`…`fc4fd512` `3140d801` | Server `EnableFapi2SecurityProfile`, `EnableFapi2MessageSigningProfile`, `SetIntrospectionResponseSigningAlgorithms`. Client registration FAPI flags + `IntrospectionResponseSigningAlgorithms`. Validation alg restriction. `OpenIddictMongoDbHelpers.CreateIndexesAsync`. BFF `EnableDistributedCaching`. | FAPI: PAR, S256, `private_key_jwt`/mTLS, DPoP/mTLS binding, PS256/ES256/EdDSA, code ≤ 60 s, no rolling refresh, loopback-IP-only http. Alg restriction via `AlgorithmValidator` (inner JWS only). DPoP nonce retry regenerates `client_assertion`. Userinfo sends DPoP + Bearer challenges. EF6 serializable `ReferenceId` uniqueness (all EF6 users). ID0989/ID0990 startup checks. |
| P16 SAML IdP extras | `ac932d04`…`35e13526` | `OpenIddictServerSamlOptions` `DataEncryptionAlgorithm`, `KeyTransportAlgorithm`, `EnableArtifactBinding`, `ArtifactLifetime`, `EnableRequestReplayProtection`, `WantAuthenticationRequestsSigned`; SP `EncryptAssertions`, `AssertionConsumerServiceBindings`; `IOpenIddictServerSamlReplayCache`, `IOpenIddictServerSamlArtifactStore`; `/saml/artifact`. | **Replay protection on by default** (reused AuthnRequest ID → 400; state single-use). Replay cache fails closed. Sign-then-encrypt (AES-GCM/CBC, RSA-OAEP). HTTP-Artifact (redirect encoding) + signed SOAP ArtifactResolve. Service constructor gained 2 parameters. |
| P17 SAML SP | `50b6f1b4`…`2063246c` | Packages `OpenIddict.Client.Saml` (net48 + net10.0), `.AspNetCore`, `.Owin`; `UseSaml()`, registrations + `IOpenIddictClientSamlRegistrationProvider`, replay cache, metadata retriever, `OpenIddictClientSamlService`. | New packages, opt-in. Registration lookups cached (5 min, 4096 entries, `ClearCache()`). Metadata `validUntil`/`cacheDuration` honoured; https SSO only; file/UNC metadata blocked for dynamic registrations. Generic status error text. Separate from `OpenIddictClientService`. |
| P11.5b/P18 admin UI | `96f2a233`…`ebde2314` `336ab92f` `b911f7ff` `ee6d9e75` `fe9e453e` | Package `OpenIddict.Server.AspNetCore.AdminUI`: `AddOpenIddictAdminUI`, `MapOpenIddictAdminUI(policy, prefix)`; template `--admin-ui`. Sessions list/details/terminate. | Opt-in, static SSR + antiforgery. Redirect URIs round-trip byte-identical. Route conflicts → ID0684. `ResolveLogoutParticipants` validates issuer before revoking (affects `TerminateSessionAsync` and end-session). |
| P19 SAML SLO | `899d5fb4`…`08c2205e` | `OpenIddictServerSamlLogoutService` (`ProcessLogoutRequestAsync`, `StartLogoutAsync`, `ProcessRejectedLogoutResponseAsync`, `ProcessSoapLogoutRequestAsync`, `IsLocalUrl`), `AcceptLogoutRequestsWithoutSessionIndex`; `/saml/slo`. | Redirect/POST chain + inbound/outbound SOAP. Strict NameID (value, Format, qualifiers) and SessionIndex required. Failed participant → `PartialLogout`. Local return URLs only. SPs with Redirect/POST SLO need signing certificates (ID01007). Terminates OIDC sessions too. |

### 4.1 Test run at `fe9e453e` (this run)

All 38 test projects built and run for every target framework (repo SDK 10.0.400, `-p:Supports{Android,IOS,MacCatalyst,MacOS}Targeting=false`). **0 failures.** `OpenIddict.slnx` builds except the MAUI sandbox (`maui-tizen` workload missing).

| Suite | net10.0 | net48 |
|---|---|---|
| Abstractions | 1,463 | 1,463 |
| Core | 679 | 679 |
| Server unit | 900 | 893 |
| Server ASP.NET Core integration (incl. admin API, DCR, logout) | 1,911 | — |
| Server OWIN integration | — | 1,840 |
| Server System.Net.Http | 67 | 67 |
| Server Data Protection | 1 | 1 |
| Admin UI | 59 | — |
| Server SAML · ASP.NET Core · OWIN | 174 · 39 · — | 174 · — · 32 |
| Client unit | 460 | 460 |
| Client ASP.NET Core / OWIN integration · ASP.NET Core / OWIN unit | 37 · 2 | 31 · 2 |
| BFF | 74 | — |
| Client SAML · ASP.NET Core · OWIN | 72 · 15 · — | 72 · — · 13 |
| Validation unit · ASP.NET Core / OWIN integration | 124 · 30 | 124 · 30 |
| EF Core · EF6 · MongoDB · Quartz | 10 · 7 · 42 · 34 | — · 10 · 42 · 35 |
| `templates/verify.sh` | 4 builds + 18 smoke checks, 0 failures | |
| **Total** | **6,200** | **5,968** |

No tests discovered (shared source libraries or empty projects): `Client/Server/Validation.IntegrationTests`, `Client.DataProtection`, `Client.SystemIntegration`, `Client.WebIntegration`, `Server.AspNetCore`, `Server.Owin`, `Validation.AspNetCore`, `Validation.Owin`, `Validation.DataProtection`.

## 5. Remaining work (ordered)

| # | Work | Size | Dependency / risk |
|---|---|---|---|
| 1 | Push decision + upstream rebase (120 fork commits on `origin/dev`) | M | Upstream #2175/#2404 overlap |
| 2 | Conformance: OIDF FAPI 2.0, back-channel/front-channel logout, CIBA, SAML interop (ADFS/Entra/Okta/Shibboleth) | M | External environments |
| 3 | CIBA: built-in RP notification endpoint, `expired_token` push, durable/outbox delivery | M | Background scheduler / store |
| 4 | Back-channel logout + CIBA notifications: retry/outbox instead of in-request sends | M | Store design |
| 5 | DCR: `jwks_uri`, `client_secret_jwt`, external initial access tokens | M | SSRF-safe JWKS fetch |
| 6 | SAML: HTTP-POST SP notification from OIDC end-session, SP metadata import (IdP), HTTP-POST artifact encoding, SP-side SLO/artifact/redirect ACS, ECDH-ES | L | — |
| 7 | Multi-issuer: remote validation (introspection/discovery) per issuer, CIBA/mTLS aliases, split endpoint matching from issuer | M | ~100 `BaseUri` uses |
| 8 | Client RP `check_session_iframe` helper; DCR metadata for JARM algs | S | — |
| 9 | Stores: EF Core migration / MongoDB indexes for session `ExpirationDate`/`LastActivityDate` (apps own migrations) | S | — |

## 6. Risks

- **Divergence from upstream:** 120 fork-only commits; upstream back-channel logout/DCR will conflict.
- **Build environment:** SDK 10.0.400 from `.dotnet`; full `OpenIddict.slnx` needs android/maui workloads (build with `-p:Supports{Android,IOS,MacCatalyst,MacOS}Targeting=false`; MAUI sandbox still fails).
- **Behaviour changes needing release notes:**

| Area | Change |
|---|---|
| Round 1 | Device `interval`/`slow_down`; PAR limited to interactive flows; `OpenIddictKeys` table; client scheme provider decorated; DPoP proof checks; JWT introspection encryption opt-in; BFF antiforgery 401; admin API JWK stripping; SAML state re-checks |
| Sessions | Expired/revoked session → sign-in rejected; `id_token_hint` sid no longer ends sessions unless opted in; expiry not checked for lifetime-less `id_token_hint`; issuer validated before revocation |
| Front-channel | `frontchannel_logout_uri` must share origin with a redirect URI (ID2364) |
| `OpenIddict.Server.SystemNetHttp` | No Polly dependency (Microsoft.Extensions.Http) |
| Client logout | Logout tokens need `exp` (opt-out); future `iat` bounded by clock skew (BFF too); startup validation ID0760/ID0766; BFF replay cache shared with client stack (replays rejected even without `EnableDistributedCaching`) |
| CIBA | Registered `bca:dlv_mode` enforced (`unauthorized_client`); push clients cannot poll; `client_notification_token` b64token; pushed errors mapped like polled; `transaction_failed` preserved |
| JARM | Require mode: discovery lists only JWT modes; client state tokens carry `oi_rsp_mode` |
| DCR | Unsafe schemes/implicit http rejected; out-of-policy metadata rejected; tokens only from header |
| FAPI follow-ups | Userinfo sends 2 `WWW-Authenticate` headers with DPoP; EF6 `ReferenceId` serializable check (ConcurrencyException ID0986); startup ID0990 for unsatisfiable introspection algs; Mongo index names `openiddict_*` |
| SAML IdP | **Replay protection on by default** (refresh/back → 400; needs shared cache when load balanced); fail-closed cache; `WantAuthnRequestsSigned` true for custom stores; SLO NameID/SessionIndex strict; `OpenIddictServerSamlService` ctor changed |
| Admin UI | Template `--admin-ui`; default prefix collides with admin API (ID0684) |

- **Security residuals:**
  - Cross-instance replay caches (client logout `jti`, BFF, SAML IdP/SP, DPoP validation) use non-atomic `IDistributedCache`.
  - SAML replay cache fail-closed → cache flooding is a login DoS; no rate limiting.
  - Back-channel logout / CIBA notifications run inline; no outbox (lost push tokens, request latency).
  - `IsPublicAddress` check on net48 is DNS-time (rebinding TOCTOU).
  - DCR: empty `RegistrationAllowedScopes` allows any non-IAT scope; `client_credentials` registrable by default.
  - Front-channel logout with `FrontchannelLogoutSessionRequired=false` → logout CSRF (spec-permitted).
  - `EnableIdentityTokenHintSessionResolution` → leaked ID token can end sessions.
  - Browser-state binding cookie is an unkeyed hash (not a security control).
  - SAML SP: dynamic https metadata can target any host unless `AllowedDynamicMetadataHosts` set; no private-IP filter.
  - MongoDB DPoP replay protection requires `CreateIndexesAsync`; EF6 uniqueness needs real range locks.
  - JARM client accepts any advertised alg when none registered; encryption alg/enc not pinned.
  - IdP-initiated SAML SSO (opt-in) login-CSRF; `Destination` checks need forwarded headers.
