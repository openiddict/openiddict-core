# OpenIddict ⇄ Duende IdentityServer parity plan

Baseline `dev@dd0d5d7d` (8.0.0-preview.5, fork of upstream). **Plan only — do not implement until asked.** Re-check line numbers at each phase start.

**Scope:** logout/sessions · DPoP/JAR/JARM · CIBA + DCR · automatic key management · non-protocol features.
**Placement:** existing packages (exceptions in B3).

---

## Resolutions (2026-09-13)

| # | Outcome |
|---|---|
| B1 | Duende v8.0.7: SAML IdP **built-in** (parity); CIBA poll only; **no JARM**; `check_session_iframe` supported; DCR = RFC 7591 only; key mgmt = signing keys only; also RFC 9701 JWT introspection, multi-issuer add-on |
| B2 | Upstream `dev` == `dd0d5d7d`. Back-channel logout (#2175) and DCR (#2404) are milestoned `8.0.0-preview.5`; front-channel logout declined; DPoP low priority (mTLS preferred); nothing upstream for CIBA, JAR, key rotation → **P1, P2, P4, P9, P11.1 deferred until upstream preview.5 is merged** |
| B3 | All exceptions approved: `OpenIddict.Server.SystemNetHttp`, BFF YARP + template pack, admin API in `Server.AspNetCore`, SAML package |
| B4 | All schema changes accepted |
| B5 | ✅ `JsonWebKey.ComputeJwkThumbprint()`, `JsonWebKey(string)`, `JsonWebKeyConverter` exist on every IdentityModel 8.22.0 TFM |
| B6 | Not blocking until P5; D4 stands |
| B7 | Host-created sessions are upstream's contract (PR #2520) |
| Scope | **Dropped:** P3 front-channel, P7 JARM. **Added:** P12 RFC 9701 JWT introspection response |
| Build | Needs SDK 10.0.400 (installed to `.dotnet` by `eng/common/build.ps1 -restore`); full solution needs android/maui workloads, so build individual projects |

**Execution order:** P6 → P8 → P10 → P5 → P12 → P11.2 → P11.3 → P11.4 → P11.5 → P11.6; then, after upstream preview.5: P1 → P2 → P4 → P9 → P11.1.

## Progress

| Phase | Status | Commit | Notes |
|---|---|---|---|
| P6 JAR | ✅ server + client | `d5c9bff7` | Request objects are validated via a direct `ValidateTokenContext` dispatch before `ValidateAuthentication`, so the PAR handler order is unchanged. External `request_uri` is not supported. |
| P8 CIBA | ✅ server (poll) | `bbd52cbf` | Requires `SetIssuer`, token storage and non-degraded mode (ID0529). Completion goes through `OpenIddictServerService`. `slow_down`/`interval` also apply to the device flow. Signed CIBA requests and mTLS alias are not implemented. |
| P8b CIBA client | ✅ | `b67cf1f3` | `OpenIddictClientService.ChallengeUsingBackchannelAsync` / `AuthenticateWithBackchannelAsync` |
| P10 key management | ✅ | `4d19d539` | RSA-2048 sig (RS256) + enc (RSA-OAEP) keys. Key entity in EF Core/EF6/MongoDB. `OpenIddictServerKeyRing` resolves credentials per transaction (`Transaction.Credentials`). Protector: `IOpenIddictServerKeyProtector` (in `OpenIddict.Server`, default via `UseDataProtection()`). Quartz pruning is opt-in (`EnableKeyPruning`). |
| P5 DPoP | ✅ server + validation + client | `0dae3a9d`, `0a732595`, `dbc144f5` | Opt-in (`EnableDPoPSupport`, `EnableDPoPTokenBinding`). Shared helper `shared/OpenIddict.Extensions/IdentityModel/OpenIddictDPoPHelpers.cs`. Server replay: redeemed token entry (reference id = `jkt.jti`). Nonces: signed JWT (server keys), server only. Validation replay: optional `IDistributedCache`. See deviations below. |
| P12 JWT introspection | ✅ server + client + validation | `f1ff44d8`, `811b913a`, `a2c44c5a`, `9d913f9a`, `0152298e`, `f1a9a312` | Opt-in (`EnableJsonWebTokenIntrospectionResponses`, `RequireJsonWebTokenIntrospectionResponses`). Token generated through `GenerateTokenContext` (`TokenTypeIdentifiers.Private.IntrospectionResponse`), signed with the first asymmetric key from `OpenIddictServerKeyRing.ResolveCredentialsAsync`. See deviations below. |
| P11.2 dynamic providers | ✅ client + ASP.NET Core + OWIN | `ad43bd3a`, `5315d310` | `IOpenIddictClientRegistrationProvider` (`AddRegistrationProvider`), static provider registered by default. Registration init/validation extracted to `OpenIddictClientConfiguration.ConfigureRegistration`/`ValidateRegistration`. See deviations below. |
| P11.3 BFF | ✅ new package `OpenIddict.Client.AspNetCore.Bff` | `6e1aca1f` | `UseBff()`, `MapOpenIddictBffEndpoints()`, `UseOpenIddictBff()`, `AsOpenIddictBffApiEndpoint()`, `AddOpenIddictBff*AccessTokenHandler()`, `AddOpenIddictBffTransforms()` (YARP 2.3.0). Hosts store `backchannel_access_token_type`. See deviations below. |
| P11.x (others) | ⏳ | — | — |

**P5 deviations**

| Item | Behaviour |
|---|---|
| Replay (server) | Entry created as `redeemed` (no separate `TryRedeemAsync`); concurrent duplicates rely on the store's unique `ReferenceId` (EF6 has none) |
| Replay (validation) | `IDistributedCache` get-then-set, not atomic |
| Nonces | Returned only with `use_dpop_nonce` errors; not issued by the validation stack |
| Confidential clients | Refresh tokens not bound; no Bearer-downgrade check on refresh |
| Client | One `use_dpop_nonce` retry; nonces cached per authority in memory; `dpop_jkt` not sent automatically (use `GetDPoPJsonWebKeyThumbprint`); ephemeral key lost on restart |
| Client PAR + mTLS | PAR codes aren't DPoP-bound when mTLS binding can be negotiated (a client-auth certificate is registered), since mTLS wins at the token endpoint |
| Client retry | `use_dpop_nonce` retry resends the same `client_assertion`; servers with assertion `jti` replay checks reject it |
| Review fixes | Proof key resolved from a minimal JWK (`x5c` key substitution); `alg` must match `kty`/`crv` |

**P12 deviations**

| Item | Behaviour |
|---|---|
| Opt-in | No per-client permission; any authenticated confidential client sending `Accept: application/token-introspection+jwt` gets a JWT when the option is on |
| JSON fallback | Errors, anonymous callers (no `client_id`) and public clients (non-degraded mode) get plain JSON |
| Encryption | Opt-in per application: setting `intr_rsp:enc_alg` = `RSA-OAEP` (only value), `intr_rsp:enc_enc` = `A128CBC-HS256` (default) or `A256CBC-HS512` (stand-ins for RFC 9701 `introspection_encrypted_response_*`). Key: first RSA `use: enc` JWK (`alg` absent or `RSA-OAEP`). Bad setting / no key → exception (ID0552/ID0553), never plaintext. Not in degraded mode |
| Claims | `iss`, `aud`, `iat`, `token_introspection` only (no `exp`/`jti`) |
| Accept parsing | Explicit media type only (`*/*` ignored, `q=0` honoured) |
| Client/validation | Decryption uses the client/validation encryption credentials; `Accept` is replaced (not appended); JSON error responses still accepted; `introspection_signing_alg_values_supported` not enforced |
| Review fixes (`f1a9a312`) | Encryption made opt-in (was automatic when an RSA `enc` key existed); A128CBC-HS256 default; response body trimmed; tests for local-key-signed and unsigned JWE tokens |

**P11.3 deviations**

| Item | Behaviour |
|---|---|
| Package | Single package (BFF + YARP); ASP.NET Core only (no OWIN BFF) |
| Refresh | In `CookieAuthenticationEvents.OnValidatePrincipal` (all cookie schemes unless `SetCookieScheme`); `EventsType` users must call `OpenIddictClientAspNetCoreBffTokenManager.ValidatePrincipalAsync`. Refresh when token missing or `exp - 1 min` passed; unknown expiration → no refresh. Single-flight per refresh-token hash, success retained 30 s (in-memory, per instance). `invalid_grant` → principal rejected + sign-out; other errors → logged, principal kept |
| Client tokens | Cached in memory per registration/scopes/resources; tokens without `expires_in` not cached |
| DPoP | Proof when stored token type is `DPoP` (registration's `DPoPSigningCredentials`). `DelegatingHandler` retries once on `use_dpop_nonce` only for requests without content; YARP transform never retries |
| Endpoints | Login/logout via GET; logout requires `sid` query parameter when the session has a `sid` claim. Callback paths auto-added to redirection URIs and passthrough enabled (`DisableAutomaticEndpointRegistration` to opt out). Registrations must use `bff/callback/login` (or the configured path) as `RedirectUri` |
| Antiforgery | Custom header (`X-CSRF: 1`) on user endpoint, `AsOpenIddictBffApiEndpoint()` endpoints and YARP routes with `OpenIddict.Bff.AccessToken` metadata (`OpenIddict.Bff.DisableAntiforgeryCheck=true` opts out); 401 when missing. Cookie redirects → 401/403 for these endpoints |
| Back-channel logout | Logout token validated in the BFF package (not the client pipeline, pending P2/P4): registration by `iss` + `aud`, signature, lifetime, `events`, no `nonce`, `iat`, `sub`/`sid`, `jti` replay (in-memory). Sessions removed only when the cookie `SessionStore` implements `IOpenIddictClientAspNetCoreBffSessionStore` (in-memory store via `UseInMemorySessionStore()`); cookie-only sessions are not revoked (hook: `IOpenIddictClientAspNetCoreBffBackchannelLogoutHandler`) |
| Not included | Refresh token revocation on logout; anonymous `/user` response option; distributed session store |

**P11.2 deviations**

| Item | Behaviour |
|---|---|
| Persistence | No `ClientRegistration` entity: custom (e.g. DB-backed or in-memory) providers only |
| Provider lifetime | Resolved from the root container (singleton); scoped dependencies need `IServiceScopeFactory` |
| Resolution order | Static options first; id lookups: static → cache → providers in registration order. Issuer/provider-name/list lookups query every provider each time |
| Cache | By `RegistrationId`, `DynamicRegistrationCacheLifetime` (default 30 min, `null`/zero disables). Keeps the configuration manager. No invalidation API: removed/changed registrations live until expiry |
| Validation | Same per-registration checks as static ones, plus: `RedirectUri`/`PostLogoutRedirectUri` must be in `RedirectionEndpointUris`/`PostLogoutRedirectionEndpointUris` (ID0555/ID0556), id must not match a static one (ID0557, case-insensitive), id returned for `FindByIdAsync` must match (ID0558). Failure → `InvalidOperationException` ID0554 |
| Demand validation | Sync "0 or >1 registrations" checks removed from `Validate*Demand`; the resolve handlers throw the same ID0304/ID0305/ID0355 |
| Web providers | `ConfigureProvider`/`ValidateProvider` now `[EditorBrowsable(Advanced)]`; dynamic web-provider registrations must call them (not idempotent: once per instance) |
| ASP.NET Core | `IAuthenticationSchemeProvider` decorated (`OpenIddictClientAspNetCoreSchemeProvider`): unknown scheme → forwarder scheme if exactly one registration has that provider name; also listed in `GetAllSchemesAsync`. Off with `DisableAutomaticAuthenticationSchemeForwarding`. Replacing the scheme provider after `UseAspNetCore()` bypasses it |
| OWIN | Forwarded challenge/sign-out/authenticate and `GetAuthenticationTypes()` fall back to dynamic provider names (`OpenIddictClientOwinForwardedTypes`); forwarded challenge lookup now only runs on 401/403 |
| Uniqueness | Dynamic provider-name duplicates aren't rejected at startup; ambiguous names aren't forwarded and fail with ID0409 when used |
| Review fixes | Cached instance reused only if issuer/provider name/client id are unchanged (was: same id → stale registration returned for another issuer); cache checked before allocating configuration manager/DPoP key; expired entries purged on insert |

## 0. Blocking — verify before coding

| # | Verify | How |
|---|---|---|
| B1 | Current Duende feature set: SAML IdP? CIBA modes (poll only?)? JARM (likely not Duende)? `check_session_iframe` still supported? | Duende docs and release notes; update §2 |
| B2 | Upstream (`openiddict/openiddict-core`) already working on DPoP, back-channel logout, JAR, DCR, CIBA, key rotation? | Search upstream issues/PRs/branches; decide per phase: PR / fork-only / wait |
| B3 | Sign-off for package exceptions: P2 server outbound HTTP (`OpenIddict.Server.SystemNetHttp`), P11.3 YARP, P11.4 template pack, P11.5 admin API in `Server.AspNetCore`, P11.6 SAML package | Yes/no per item; fallbacks are noted in the phases |
| B4 | Schema changes accepted for 8.0: `Session.ExpirationDate` / `LastActivityDate`, new **Key** entity, optional **ClientRegistration** entity | Maintainer decision |
| B5 | IdentityModel 8.22.0 on all TFMs (`OpenIddict.Server.csproj:4`): `JsonWebKey.ComputeJwkThumbprint()` and building a key from the header `jwk`. Not used anywhere in `src` today. | Scratchpad spike per TFM; else an internal RFC 7638 helper |
| B6 | Replay strategy (D4) load: one token-row insert per DPoP request. No cache infrastructure exists; no client-assertion `jti` replay check. | Throughput estimate |
| B7 | Sessions are **created by the host**, not the server (`sandbox/.../AuthorizationController.cs:230-251`; `login_id` is sandbox-only, `UserClaimsPrincipalFactory.cs:32`). Is this the long-term contract? | Confirm with upstream |

## 1. Decisions

**Yours:** all 4 groups · existing packages · non-protocol features planned · one file.

**Taken by this plan (override before coding):**

| # | Default | Reason |
|---|---|---|
| D1 | Logout client metadata stored in app `Settings` (no columns) | No migration; same as token lifetimes (`OpenIddictConstants.cs:569-587`) |
| D2 | End-session sign-out revokes session + tokens; opt out with `DisableSessionRevocationOnSignOut()` | Duende behaviour |
| D3 | Back-channel logout sent in-request, in parallel, 5 s timeout, through an overridable event | Minimal dependencies |
| D4 | DPoP replay: server uses token entry + `TryRedeemAsync`; validation stack uses optional `IDistributedCache` | Reuses `OpenIddictServerHandlers.cs:2830` |
| D5 | JAR per RFC 9101: outer params ignored; external `request_uri` unsupported | Matches PAR restore (`…Authentication.cs:648-691`); SSRF |
| D6 | CIBA poll only | Duende parity |
| D7 | New `OpenIddictServerService` (CIBA completion, session admin) | Hides degraded-mode differences |
| D8 | DCR management at `{registration endpoint}?client_id=` | Endpoint matching is exact-URI (`OpenIddictServerHandlers.cs:169-181`) |
| D9 | Registration access token = private reference token type | Reuses `ValidateTokenEntry` (`…Protection.cs:1174`) |
| D10 | Key entity + store; `IOpenIddictKeyProtector` (default in `Server.DataProtection`) | Web farms |
| D11 | Credentials resolved per transaction, not options | Options are built once; sort/kid only in `PostConfigure` (`OpenIddictServerConfiguration.cs:83-102`) |
| D12 | `slow_down` / `interval` implemented generically (device + CIBA) | The server never emits them today |

## 2. Gap matrix

| Feature | Duende | OpenIddict today | Phase |
|---|---|---|---|
| Code+PKCE, CC, refresh, device, token exchange, PAR, mTLS, `private_key_jwt`, resource indicators | ✅ | ✅ (`OpenIddictServerBuilder.cs:886-2420`) | — |
| Server-side sessions | ✅ | ⚠️ entity + validation (`…Protection.cs:1411`); no revoke/expiry/admin | P1, P11.1 |
| Back-channel logout | ✅ | ❌ | P2 |
| Front-channel logout / session mgmt | ✅ | ❌ | P3 |
| RP-side logout (client stack) | n/a | ❌ (`OpenIddictClientEndpointType.cs:27`) | P4 |
| DPoP | ✅ | ❌ | P5 |
| JAR by value | ✅ | ❌ rejected (`…Authentication.cs:443-454`, `:2525`) | P6 |
| JARM | ❓ | ❌ (`OpenIddictConstants.cs:522-527`) | P7 |
| CIBA | ✅ | ❌ | P8 |
| DCR | ✅ | ❌ | P9 |
| Auto key management | ✅ | ❌ static keys only (`OpenIddictServerBuilder.cs:488-872`) | P10 |
| Dynamic providers | ✅ | ⚠️ static list (`OpenIddictClientOptions.cs:101`) | P11.2 |
| BFF | ✅ | ⚠️ manual refresh (sandbox `HomeController.cs:46-94`) | P11.3 |
| UI templates / admin API / SAML | ✅ / ❌ / ❓ | ❌ | P11.4-6 |

## 3. Conventions (all phases)

- **Handlers:** `sealed` handler + `Descriptor` (template `…Authentication.cs:426-458`). Filters in `*HandlerFilters.cs`, registered in `*Extensions.cs`.
- **Resource IDs:** next free are ID0524, ID2211, ID4023, ID6298. Reserve a block per phase.
- **Constants:** `OpenIddictConstants.cs` only.
- **Hosts:** every host change is made in both ASP.NET Core **and** OWIN.
- **Store-dependent handlers:** add `RequireDegradedModeDisabled` / `RequireTokenStorageEnabled`, plus the degraded-mode configuration errors (`OpenIddictServerConfiguration.cs:519-614`).
- **New endpoint checklist:**
  - `OpenIddictServerEndpointType.cs` (next free value 12)
  - in `OpenIddictServerHandlers.cs`: matching `:169-181`, `ValidateAuthenticationDemand` `:257`, `EvaluateValidatedTokens` `:289`, `ResolveValidatedTokens` `:455`, client skip lists `:940-1219`, `AttachDefaultChallengeError` `:2499`, `ValidateSignInDemand` `:2700`, `EvaluateGeneratedTokens` `:3180`, `AttachSignInParameters` `:5456`
  - options `:78-189`; builder (template `:1107-1141`); config uniqueness `:224-241` and mTLS checks `:434-466`
  - discovery `AttachEndpoints` `:387`
  - host handler files + principal selection (`OpenIddictServerAspNetCoreHandler.cs:163-185`); `AttachHttpResponseCode` (`…AspNetCoreHandlers.cs:908`)
  - inference theory test (`OpenIddictServerIntegrationTests.cs:40-86`)
- **New entity checklist:** mirror commits `4f6882bc` + `6665db78` (Abstractions, Core, EF6, EF Core, MongoDB, Quartz, tests).
- **Sandbox:** demonstrates features only; it never drives library code.

---

## P1 — Session revocation & lifecycle

| Change | Where |
|---|---|
| Store: `RevokeAsync`, `RevokeByLoginIdAsync`, `RevokeBySubjectAsync`, `Get/SetExpirationDateAsync`, `Get/SetLastActivityDateAsync` | `IOpenIddictSessionStore.cs` after `:258` |
| Token store/manager: `FindBySessionIdAsync`, `RevokeBySessionIdAsync` | `IOpenIddictTokenStore.cs:345`, `IOpenIddictTokenManager.cs:440` |
| Manager: `TryRevokeAsync` (copy `OpenIddictAuthorizationManager.cs:756`), `RevokeBy*` | `OpenIddictSessionManager.cs` after `:733` |
| Bulk revoke implementations | EF Core copies `…CoreTokenStore.cs:790-849`; EF6 copies `…TokenStore.cs:746-791`; MongoDB copies `…MongoDbTokenStore.cs:498-510` |
| New columns + descriptor; `PruneAsync` also prunes expired sessions | Session models, configs (`…CoreSessionConfiguration.cs:37-89`), stores (EF Core `:495`, EF6 `:528`, MongoDB `:393`) |
| `ResolveSignOutSession`: session id from property `.session_id` or `IdentityTokenHintPrincipal.GetSessionId()` (`…Session.cs:506`) | `OpenIddictServerHandlers.cs` after `ValidateSignOutDemand` `:5543` |
| `RevokeSessionEntry`: `TryRevokeAsync` + `RevokeBySessionIdAsync` | after `RedeemLogoutTokenEntry` `:5573` |
| Expiry check; sliding renewal on refresh (throttled) | `…Protection.cs:1411-1446`, `OpenIddictValidationHandlers.Protection.cs:969-997`, `RedeemTokenEntry` `:2830` |
| Option/builder `DisableSessionRevocationOnSignOut` | `OpenIddictServerOptions.cs:449`, `OpenIddictServerBuilder.cs:2287` |

```csharp
public virtual async ValueTask<bool> TryRevokeAsync(TSession session, CancellationToken cancellationToken = default)
{
    if (await HasStatusAsync(session, Statuses.Revoked, cancellationToken)) return true;
    await Store.SetStatusAsync(session, Statuses.Revoked, cancellationToken);
    try { await UpdateAsync(session, cancellationToken); return true; }
    catch (ConcurrencyException) { return false; }
}
```

**Verify:**
- `OpenIddictSessionManagerTests.cs`: revoke, concurrency.
- `…IntegrationTests.Session.cs`: revoke from id_token_hint or properties; tokens revoked; opt-out; degraded mode.
- `…Protection.cs:868`: expired session rejected.
- `OpenIddictQuartzJobTests.cs`: expired sessions pruned.

**Risks:**
- Schema change (B4).
- Extra writes from renewal.
- Self-contained JWTs stay valid unless `EnableSessionEntryValidation` (`OpenIddictValidationBuilder.cs:602`) is enabled.

## P2 — Back-channel logout (needs P1, B3)

**Flow:** revoked session → all valid sessions with the same `LoginId` (`IOpenIddictSessionManager.cs:123`) → apps with `Settings.Logout.BackchannelUri` → one `logout_token` per app (`iss`, `aud`, `iat`, `exp`, `jti`, `events`, `sub`/`sid`, **no `nonce`**) → form POST → revoke those sessions.

| Change | Where |
|---|---|
| Constants: `Claims.Events`, `JsonWebTokenTypes.LogoutToken="logout+jwt"`, `Metadata.BackchannelLogout{Supported,SessionSupported}`, `Parameters.LogoutToken`, `Settings.Logout.*`, `TokenTypeIdentifiers.Private.LogoutToken` | `OpenIddictConstants.cs` |
| Descriptor helpers; manager validates URI (absolute, HTTPS, no fragment; reuse `:1317-1351`) | `OpenIddictApplicationDescriptor.cs:213`, `OpenIddictApplicationManager.cs:1244` |
| Events: `ProcessBackchannelLogoutContext`, `ApplyBackchannelLogoutRequestContext` (transport hook) | new `OpenIddictServerEvents.Logout.cs` |
| Handlers: `ResolveBackchannelLogoutTargets`, `PrepareLogoutTokenPrincipal`, `GenerateLogoutTokens` (copy `GenerateIdentityToken` `:5222-5281`), `SendBackchannelLogoutRequests`, `RevokeLoggedOutSessions` | new `OpenIddictServerHandlers.Logout.cs` |
| Logout token signed like an id token (asymmetric, no encryption); `typ` mapping | `…Protection.cs:1472-1489`, `:1652`, `:1720-1733` |
| Transport: `OpenIddict.Server.SystemNetHttp` mirroring `OpenIddictClientSystemNetHttpHandlers.cs:38-992`. **Fallback:** handlers inside `OpenIddict.Server` via `IHttpClientFactory` | new package / `OpenIddict.Server` |
| Options: `EnableBackchannelLogout`, `BackchannelLogoutTimeout`, `LogoutTokenLifetime`; config checks | `OpenIddictServerOptions.cs`, `OpenIddictServerConfiguration.cs:207` |
| Discovery flags | `…Discovery.cs:855-864` |

**Verify:**
- New `…IntegrationTests.Logout.cs`: token shape; one POST per app; LoginId fan-out; a timeout does not fail sign-out; custom transport.
- Discovery test (`:1051`).
- OIDF back-channel logout conformance.

**Risks:** logout latency; SSRF (HTTPS + allow-list option); sessions without a LoginId are not fanned out (B7).

## P3 — Front-channel logout (needs P1)

| Change | Where |
|---|---|
| `ApplyEndSessionResponseContext.FrontchannelLogoutUris`; `AttachFrontchannelLogoutUris` (shared fan-out helper in `OpenIddictServerHelpers.cs`); adds `?iss=&sid=` | `…Session.cs` after `:937` |
| `ProcessFrontchannelLogoutResponse`: iframes page + CSP `frame-src` + redirect after load or 3 s | `…AspNetCoreHandlers.Session.cs:100/153`, OWIN `:103/160` |
| Passthrough access: `GetFrontchannelLogoutUris()` | host extensions |
| `Metadata.FrontchannelLogout{Supported,SessionSupported}` | `…Discovery.cs:855-864` |

**P3b:** `check_session_iframe`. Recommend skipping (third-party cookie blocking).

**Verify:** host tests check the HTML iframes and redirect, and that no page is rendered without front-channel URIs.

**Risk:** browsers block third-party cookies, so front-channel is unreliable. Recommend back-channel.

## P4 — Client RP logout

| Change | Where |
|---|---|
| Endpoint types `BackchannelLogout`, `FrontchannelLogout`; options, builder | `OpenIddictClientEndpointType.cs:27`, `OpenIddictClientOptions.cs` |
| Validate `logout_token`: registration by `iss` (`OpenIddictClientService.cs:69`), keys (`…Client…Protection.cs:175`), `aud`, `iat`, `events`, `sub`/`sid`, no `nonce`, `jti` replay (pattern `RedeemStateTokenEntry` `:819`) | new `OpenIddictClientHandlers.Logout.cs` |
| `Handle*LogoutRequestContext` exposes iss/sub/sid; passthrough | `OpenIddictClientAspNetCoreOptions.cs:44-52`, OWIN |

**Verify:** client integration tests against an in-memory server with P2 enabled.

**Risk:** the app needs a server-side ticket store to act on logout (provided in P11.3).

## P5 — DPoP (blocked by B5, B6)

**Constants:**
- `Schemes.DPoP`, `TokenTypes.DPoP`, `Headers.DPoP` / `DPoPNonce`
- `JsonWebTokenTypes.DPoPProof="dpop+jwt"`, `TokenTypeIdentifiers.Private.DPoPProof`
- `Claims.{HttpMethod "htm", HttpUri "htu", "ath"}`, `Parameters.DPoPJkt`
- `Errors.{InvalidDPoPProof, UseDPoPNonce}`, `Metadata.DPoPSigningAlgValuesSupported`
- `TokenBindingMethods.Private.DPoP`, `Requirements.Features.DPoP="ft:dpop"`

| Stack | Change | Where |
|---|---|---|
| Server host | `ExtractDPoPProof` (single `DPoP` header → `Transaction.DPoPProof`) | next to `ExtractClientCertificate` `…AspNetCoreHandlers.cs:682`, OWIN `:744`; `OpenIddictServerTransaction.cs:26` |
| Server host | Accept `DPoP <token>` | `ExtractAccessToken` `…AspNetCoreHandlers.cs:815-852`, OWIN `:892` |
| Server | Enable proof for token, PAR, userinfo; `ValidateDPoPProof` / claims / binding (`htm`, `htu` without query, `iat` window, `ath`) / `RedeemDPoPProof` | `OpenIddictServerHandlers.cs:289`, after `:849` |
| Server | Proof key from `jwk` header; reject private members and symmetric algs; `typ` map; skip token-entry restore | `…Protection.cs:86-101`, `:534-560`, `:325-329`, `:756-761` |
| Server | `dpop_jkt` at authorize/PAR → `Claims.Private.DPoPJwkThumbprint` in code; must match at redemption | `…Authentication.cs:1119`, `:3065` |
| Server | `cnf.jkt` binding (access; refresh for public clients only; token exchange) | `OpenIddictServerHandlers.cs:3548-3561`, `:4255-4297`, `:3987-4040` |
| Server | `token_type=DPoP` | `:5366`, `:5418-5420` |
| Server | `jkt` branch before the ID2196 throw; reject downgrade to Bearer | `…Protection.cs:1112-1165` |
| Server | Introspection `token_type=DPoP`; `WWW-Authenticate: DPoP algs=` | `…Introspection.cs:749-762`; `…AspNetCoreHandlers.cs:1048`, OWIN `:1239` |
| Server | Per-client/global requirement; discovery algs; optional nonces (5b) | pattern `…Authentication.cs:1906`; `…Discovery.cs:745` |
| Validation | Accept `DPoP` scheme; `ExtractDPoPProof`; proof handlers; `jkt` branches; challenge | `…ValidationAspNetCoreHandlers.cs:193-199`, `:310`, `:596`; OWIN `:195`, `:313`, `:747`; `…Validation…Protection.cs:818-871`; `OpenIddictValidationHandlers.cs:890-943` |
| Shared | Extract the PoP check (3 copies today) into a `shared/` helper | — |
| Client | Negotiate DPoP; `DPoPSigningCredentials` (ephemeral P-256 default); `GenerateDPoPProof` (copy `:2872`); header + scheme; `use_dpop_nonce` retry; `CreateDPoPProofAsync` API | `OpenIddictClientHandlers.cs:2453`, `:4126`, `:6342`; `OpenIddictClientConfiguration.cs:37`; `…SystemNetHttpHandlers.Userinfo.cs:75`, `:756` |

**Verify:**
- Server/validation matrices: valid proof; bad `htm`/`htu`/`iat`; replay; private `jwk`; symmetric alg; `ath` mismatch; Bearer downgrade; refresh binding for public clients only; `dpop_jkt` mismatch; introspection; discovery.
- FAPI 2.0 DPoP conformance.

**Risks:** DB write per request (B6); `htu` behind proxies (forwarded headers); ML-DSA thumbprints undefined → EC/RSA only; the client ephemeral key breaks refresh after restart.

## P6 — JAR by value

| Change | Where |
|---|---|
| Constants `JsonWebTokenTypes.AuthorizationRequest="oauth-authz-req+jwt"`, `TokenTypeIdentifiers.Private.RequestObject`, `Requirements.Features.JwtSecuredAuthorizationRequests`, `Metadata.RequireSignedRequestObject` | `OpenIddictConstants.cs` |
| `EnableRequestObjectSupport()`, `RequireRequestObjects()`, `RequestObjectSigningAlgorithms`, `RequestObjectLifetime` | options/builder |
| Reject only when disabled; `request` + `request_uri` together → `invalid_request` | `…Authentication.cs:426-458`, `:2525-2553` |
| `ValidateRequestObject`: `iss == client_id`; `aud` = issuer; no nested `request`/`request_uri`; no `alg=none`; errors → `invalid_request_object` | `OpenIddictServerHandlers.cs:289`, `:455`, after `:849` |
| Generalize client key params to accept the `typ` set | `…Protection.cs:103-171`, `:137-141`, `:534-560` |
| `RestoreRequestObjectParameters` (copy `:648-691`); PAR path serializes the merged request (`OpenIddictServerHandlers.cs:4145`) | `…Authentication.cs` after `:631` |
| PAR: move `ValidatePushedAuthentication` (`:3276`) before `:2641` | `…Authentication.cs` |
| Discovery `request_parameter_supported`, algs | `…Discovery.cs:858` |
| Optional: JWE request objects; `jti` replay | — |
| Client: `RequestObjectMode`; `GenerateRequestObject` (copy `:6710`); attach + strip params (`:6586`, `:7296`) | `OpenIddictClientHandlers.cs` |

**Verify:**
- Replace tests `…Authentication.cs:135` and `:3231` with enabled/disabled theories.
- New cases: outer params ignored; bad `aud`/`iss`; nested `request_uri`; `alg=none`; expired; PAR+JAR.
- Update the discovery assertion at `:989`.

**Risk:** PAR error precedence changes (release note).

## P7 — JARM (confirm B1)

| Change | Where |
|---|---|
| `ResponseModes.{Jwt, QueryJwt, FragmentJwt, FormPostJwt}`, `Parameters.Response`, `Metadata.Authorization{Signing,Encryption}*`, `TokenTypeIdentifiers.Private.AuthorizationResponse` | `OpenIddictConstants.cs:522-527` |
| New `IsJwtResponseMode()`; existing helpers unchanged | `OpenIddictExtensions.cs:398-457` |
| `AllowJwtResponseModes()` | `OpenIddictServerOptions.cs:560-565` |
| Mode validation (`query.jwt` + `token`/`id_token` rejected unless encrypted) | `…Authentication.cs:901-973`, `:2846-2918` |
| `jwt` → `query.jwt` / `fragment.jwt` | `InferResponseMode` `:2140-2170` |
| `GenerateAuthorizationResponseToken` wraps all params (errors too) into `response` | after `AttachIssuer` `:2213`; credentials `…Protection.cs:1472` |
| Hosts accept `.jwt` variants | `…AspNetCoreHandlers.Authentication.cs:147`, `:230`, `:284`; OWIN `:154`, `:237`, `:295` |
| Discovery | `…Discovery.cs:528-549` |
| Client: negotiate; `ExtractJwtAuthorizationResponse` before `:605` | `OpenIddictClientHandlers.cs:5640`, host variants |

**Verify:** 4 modes; wrapped errors; `aud`/`exp`; tampered JWT rejected on the client.

**Risks:** URL length; encryption needs client `use=enc` keys.

## P8 — CIBA (poll; needs D7, D12; P6 optional)

| Change | Where |
|---|---|
| Constants: `GrantTypes.Ciba`, permissions, `Parameters.{AuthReqId, LoginHintToken, BindingMessage, RequestedExpiry, ClientNotificationToken}`, `Errors.{ExpiredLoginHintToken, UnknownUserId, InvalidBindingMessage, MissingUserCode, InvalidUserCode}`, `Metadata.Backchannel*`, private token type + claims | `OpenIddictConstants.cs` |
| Endpoint `BackchannelAuthentication=12` (§3 checklist); authenticated clients only | pattern `OpenIddictServerHandlers.cs:979-981` |
| Events + handlers (copy device: `…Events.Device.cs:17-111`, `…Handlers.Device.cs:19-601`): scope has `openid`; exactly one hint; binding message; requested expiry; user code | new `*.BackchannelAuthentication.cs` |
| Host resolves user → `SignIn(sub)`; passthrough builder + filter | `…AspNetCoreBuilder.cs:94`, filter `:174`; OWIN; `ValidateSignInDemand` `:2737` |
| `auth_req_id`: Inactive reference token (copy `:3676-3763`, `:4661-4734`); response `expires_in`, `interval` | `…Protection.cs:1529-1538`, `:5456` |
| `OpenIddictServerService.Approve/Reject/GetBackchannelAuthenticationRequestAsync` (mirror `:4983-5045`, `:2546-2592`) | new `OpenIddictServerService.cs` |
| Token grant (copy device: `…Exchange.cs:582-610`, `:1216`, `:1573`, `:2085`, `:2163`); principal arm; `AllowCustomFlow` exclusion | `…AspNetCoreHandler.cs:175`; `OpenIddictServerBuilder.cs:914` |
| Generic `slow_down` (`oi_last_poll` property) + `interval` in device response | `…Protection.cs:1265` |
| Config checks (mirror `:252-278`, `:356`, `:532-613`); discovery `poll` | `OpenIddictServerConfiguration.cs` |
| Client `ChallengeUsingBackchannelAsync` / `AuthenticateWithBackchannelAsync` | `OpenIddictClientService.cs:590`, `:712` |
| 8b (beyond Duende): ping/push, reusing the P2 transport | — |

**Verify:**
- Hints; unknown user; pending → approve; reject → `access_denied`; expiry; `slow_down`.
- Add the missing device-flow `authorization_pending`/`slow_down` tests.
- Inference theory; configuration tests; OIDF CIBA conformance.

**Risks:** device-flow behaviour change (D12, release note); extra write per poll.

## P9 — DCR (RFC 7591/7592)

| Change | Where |
|---|---|
| Constants: `Metadata.RegistrationEndpoint`, `Errors.{InvalidRedirectUri, InvalidClientMetadata, InvalidSoftwareStatement, UnapprovedSoftwareStatement}`, new `ClientMetadata` class, `Permissions.Endpoints.Registration`, `TokenTypeIdentifiers.Private.RegistrationAccessToken` | `OpenIddictConstants.cs` |
| Endpoint `Registration=13`: POST create; GET/PUT/DELETE with `?client_id=` | §3 checklist |
| `ExtractJsonRequest` (JSON body, size limit) | `…AspNetCoreHandlers.cs` near `:543`; OWIN |
| Create auth: initial access token = own access token with scope `dcr` (or `Open` policy); manage auth: registration token bound to the app | `OpenIddictServerHandlers.cs:1548-1616`, `:295`, `:457` |
| Metadata → descriptor mapping, table below | new `…Handlers.Registration.cs`; `OpenIddictApplicationDescriptor.cs:15-92` |
| Custom policy event `ValidateClientRegistrationContext`; optional software statement | same |
| Create: random `client_id` + secret; `CreateAsync` (`OpenIddictApplicationManager.cs:244`); `ValidationException` → `invalid_redirect_uri` / `invalid_client_metadata`; PUT `:1216`; DELETE `:276` + `RevokeByApplicationIdAsync` | same |
| Status codes 201/200/204; empty-body JSON | `…AspNetCoreHandlers.cs:908-965`, `:1166`; OWIN `:985`, `:1357` |
| Discovery `registration_endpoint` | `…Discovery.cs:387` |

**Metadata → descriptor mapping:**

| Metadata | Maps to |
|---|---|
| `redirect_uris`, `post_logout_redirect_uris` | URI sets |
| `grant_types`, `response_types`, `scope` | permissions (+ implied endpoints) |
| `token_endpoint_auth_method` | `none` → public; secret methods → generated secret; `private_key_jwt` → `jwks` required; `tls_*` → **verify how mTLS clients are stored before coding** |
| `client_name` | `DisplayName(s)` |
| `jwks` | `JsonWebKeySet` |
| `jwks_uri` | rejected |
| `*_logout_*` | `Settings.Logout.*` |
| rest | `Properties` |

**Verify:**
- Create public / confidential / `private_key_jwt` clients, then run client_credentials.
- Invalid redirect; `jwks_uri` rejected; token missing or wrong → 401; GET/PUT/DELETE; DELETE revokes tokens; policy handler rejects.

**Risks:** abuse in open mode (default requires a token); unknown mTLS mapping; new JSON extraction path.

## P10 — Automatic key management (B4, D10, D11)

| Change | Where |
|---|---|
| Key entity: `KeyId`, `Use`, `Algorithm`, `ProtectedData`, `Creation/Activation/Expiration/RetirementDate`, `Properties`; manager `FindActiveAsync`, `ListPublishableAsync`, `PruneAsync` | §3 entity checklist |
| `KeyManagement` options (rotation 90 d, propagation 14 d, retention 14 d, cache 24 h, algs); `EnableAutomaticKeyManagement()` | `OpenIddictServerOptions.cs:59` |
| `OpenIddictServerKeyRing` singleton: cache, lazy create, announce before use, merge static keys | new |
| `ResolveServerCredentials` (first handler) → `Transaction.SigningCredentials` / `EncryptionCredentials`; move `Compare` / `GetKeyIdentifier` to `OpenIddictHelpers` | `OpenIddictServerTransaction.cs:26`; `OpenIddictServerConfiguration.cs:104-203` |
| Replace option reads | `…Protection.cs:1466-1489`, `:173-175`; `OpenIddictServerHandlers.cs:5079-5081`; `…Discovery.cs:762`, `:1199`; plus a grep audit |
| Skip ID0085–ID0088 when enabled | `OpenIddictServerConfiguration.cs:405-431` |
| `IOpenIddictKeyProtector`; default in `Server.DataProtection` (`…Constants.cs:37`); OWIN requires one to be registered | Abstractions |
| Local validation: key-ring-backed `IConfigurationManager` instead of the static copy | `OpenIddictValidationServerIntegrationConfiguration.cs:33-58` |
| Optional Quartz: create successor, prune retired | `OpenIddictQuartzJob.cs` after `:196`; `OpenIddictQuartzOptions.cs` |

**Verify:**
- Key ring state machine with `FakeTimeProvider`.
- JWKS has announced + active keys; tokens signed with the active kid; retired key validates during retention; static + auto coexist.
- Local validation picks up rotation; 2-instance manual test.

**Risks:** a missed credential read signs with an unpublished key (grep + reflection test); DB becomes required for issuance (cache); losing the DataProtection key ring makes keys unreadable.

## P11 — Non-protocol

| Item | Plan | Where / fallback |
|---|---|---|
| **11.1 Session admin** (needs P1, P2) | `OpenIddictServerService.QuerySessionsAsync` / `RevokeSessionsAsync` (tokens, authorizations `IOpenIddictAuthorizationManager.cs:365`, back-channel logout); Quartz option: expired sessions trigger logout | `OpenIddictQuartzJob.cs:153-196` |
| **11.2 Dynamic providers** | `IOpenIddictClientRegistrationProvider` behind `OpenIddictClientService.cs:40-156`; extract registration init from `OpenIddictClientConfiguration.cs:37-104`; dynamic registrations must use declared redirect URIs (state token `RegistrationId` `:1100-1133`); replace `Options.Registrations` fallbacks (`OpenIddictClientHandlers.cs:419`, `:493`, `:4898`, `:4983`, `:7356`, `:7396`, `:8161`, `:8201`, `:8899`, `:8984`); expose generated `ConfigureProvider` (`…Generator.cs:928`) | Persistence entity optional (B4); schemes via `ProviderName` (sandbox `AuthorizationController.cs:139-142`) |
| **11.3 BFF** (`Client.AspNetCore`) | Cookie `OnValidatePrincipal` auto-refresh (generalizes `HomeController.cs:46-94`, keyed lock); `DelegatingHandler` for user/client tokens (DPoP-aware); `MapOpenIddictBffEndpoints()` (login, logout, user with `X-CSRF`, back-channel → `ITicketStore`) | YARP proxy needs B3; fallback is a docs snippet |
| **11.4 UI templates** | `templates/`: `server-identity`, `server-empty`, `bff`, from generalized sandbox (`AuthorizationController.cs:59-530`, `AccountController.cs`) | Pack publish needs B3; fallback is in-repo folders |
| **11.5 Admin API** | `MapOpenIddictManagementEndpoints()` CRUD via managers; policy name required | `Server.AspNetCore` (B3); UI only as template |
| **11.6 SAML IdP** | Gate B1 + B3. Separate plan: metadata, SP registry, Redirect/POST bindings, XML DSig, SLO via P1/P2, XSW/XXE hardening | Recommend third-party (`README.md:37-39`) |

**Verify:**
- 11.1: service + Quartz tests.
- 11.2: runtime registration test.
- 11.3: TestServer tests (refresh, CSRF, logout).
- 11.4: CI runs `dotnet new` + build + discovery smoke test.

**Risks:** API surface commitments (11.5); XML signature attack surface (11.6); ticket-store dependency (11.3).

---

## P12 — JWT introspection response (RFC 9701)

| Change | Where |
|---|---|
| `JsonWebTokenTypes.IntrospectionResponse="token-introspection+jwt"`, `TokenTypeIdentifiers.Private.IntrospectionResponse`, `Metadata.IntrospectionSigningAlgValuesSupported` / `IntrospectionEncryption*` | `OpenIddictConstants.cs` |
| Host: detect `Accept: application/token-introspection+jwt` → `Transaction` flag | `…AspNetCoreHandlers.Introspection.cs:15-31`, OWIN |
| After the response is built (`…Introspection.cs:227-278`): wrap in a JWT (`iss`, `aud`=client_id, `iat`, `token_introspection` claim) signed like an id token | `…Introspection.cs`, `…Protection.cs:1472` |
| `ProcessJsonResponse` variant writing `application/token-introspection+jwt` | `…AspNetCoreHandlers.cs:1166`, OWIN `:1357` |
| Validation stack: request + validate JWT introspection responses (optional) | `OpenIddictValidationHandlers.Introspection.cs` |

**Verify:** JSON response unchanged without the header; JWT claims/signature with it; discovery algs.

## 4. Order

`B1–B7` → **P1 → P2 → P5 → P6 → P10 → P9 → P8 → P3 → P4 → P7 → P11.x**

Dependencies:
- P2, P3, P11.1 need P1; P4 needs P2 and P3 (for interop).
- P7 and P8 benefit from P6; P8 needs D7 and D12; P11.3 uses P4 and P5.

## 5. Every phase

1. Build all TFMs (analyzers clean).
2. `dotnet test OpenIddict.slnx` (ASP.NET Core + OWIN runners).
3. Review the public API diff.
4. Sandbox smoke test; audit the diff for sample-specific code.
5. Conformance suite where applicable.
6. Release notes for behaviour changes (D2, D12, P6 PAR precedence).
7. Commit at the milestone.

## 6. Cross-phase risks

| Risk | Mitigation |
|---|---|
| Upstream divergence (B2) | Coordinate; send P1 upstream first |
| Schema churn (B4) | Batch P1, P10, P11.2 schema changes into one preview |
| Per-request DB writes | Throttles, optional cache, opt-outs |
| Parser security (`jwk`, JSON, XML) | Negative test matrices, `/security-review`, conformance suites |
| Scope vs capacity | Each phase ships independently; P11.4–6 are droppable |
