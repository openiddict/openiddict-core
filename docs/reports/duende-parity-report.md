# OpenIddict vs Duende IdentityServer — feature gap report

| | |
|---|---|
| Date | 2026-09-13 |
| OpenIddict baseline | 8.0.0-preview.5 (`dd0d5d7d`, identical to upstream `dev`) + fork branches `feature/jar`, `feature/ciba` |
| Duende reference | IdentityServer 8.0.7 (June 2026) |
| Detailed plan | [`docs/plans/duende-parity-plan.md`](../plans/duende-parity-plan.md) |

Legend: ✅ available · 🟢 implemented in this fork (not upstream) · ⚠️ partial · ❌ missing · ⏸ deferred to upstream · ⛔ dropped

## 1. Summary

- **Protocol core is already at parity:** authorization code + PKCE, client credentials, refresh, device flow, token exchange, PAR, mTLS (client auth + bound tokens), `private_key_jwt`, introspection, revocation, resource indicators, `iss` response parameter.
- **Closed in this fork:** JAR (request objects) on the server and client, and CIBA (poll mode) on the server.
- **Largest remaining gaps:** logout and sessions (back-channel logout, session management), DPoP, automatic key management, dynamic client registration, SAML, and BFF/dynamic providers.
- **Upstream is working on two of them:** back-channel logout (#2175) and DCR (#2404) are milestoned for `8.0.0-preview.5`, so the fork waits.

## 2. Gap matrix

| Feature | Duende 8 | OpenIddict | Status / next step |
|---|---|---|---|
| Code+PKCE, CC, refresh, device, token exchange, PAR, mTLS | ✅ | ✅ | — |
| JWT-secured authorization requests (RFC 9101), by value | ✅ | 🟢 | Done (`ad3476ee`) |
| JAR by reference (external `request_uri`) | ✅ (opt-in) | ❌ | Not planned (SSRF risk) |
| CIBA — poll mode | ✅ | 🟢 server | Client side next (P8b) |
| CIBA — signed requests, ping/push | ❌ ping/push | ❌ | Low priority |
| Server-side sessions | ✅ (expiry, query/terminate API) | ⚠️ entity + validation only | ⏸ P1 / P11.1 after upstream |
| Back-channel logout | ✅ | ❌ | ⏸ P2 (upstream #2175) |
| Front-channel logout | ✅ | ❌ | ⛔ declined upstream (third-party cookies) |
| OIDC Session Management (`check_session_iframe`) | ✅ | ❌ | ⛔ same reason |
| RP-side logout in client stack | n/a | ❌ | ⏸ P4 |
| DPoP (RFC 9449, incl. nonces) | ✅ | ❌ | P5 (upstream prefers mTLS) |
| JARM (`response_mode=jwt`) | ❌ | ❌ | ⛔ not parity |
| JWT introspection response (RFC 9701) | ✅ | ❌ | P12 |
| Dynamic client registration (RFC 7591) | ✅ (Configuration API) | ❌ | ⏸ P9 (upstream #2404) |
| DCR management (RFC 7592) | ❌ | ❌ | Included in P9 |
| Automatic key management | ✅ signing keys (90 d rotate / 14 d announce / 14 d retain) | ❌ static keys only | P10 (signing + encryption) |
| Dynamic external providers (OIDC/SAML) | ✅ | ⚠️ static client registrations | P11.2 |
| BFF | ✅ Duende.BFF 4.2 | ⚠️ manual token refresh (sample) | P11.3 |
| UI templates | ✅ | ⚠️ sandbox only | P11.4 |
| Admin UI | ❌ (third-party) | ❌ | P11.5 (API only) |
| SAML 2.0 IdP | ✅ built-in (v8) | ❌ | P11.6 — separate plan needed |
| FAPI 2.0 conformance report | ✅ | ❌ | Depends on DPoP + key management |
| Multi-issuer hosting | ✅ add-on | ❌ | Not planned |

## 3. OpenIddict strengths with no Duende equivalent

| Area | OpenIddict |
|---|---|
| Client stack | Full OAuth/OIDC client, including desktop/mobile integration and 100+ generated web providers |
| Hosts | ASP.NET Core **and** OWIN / .NET Framework |
| Stores | EF Core, EF6, MongoDB; Quartz pruning job |
| Licensing | Apache 2.0, no paid tiers |

## 4. Implemented in this fork

| Phase | Commit | What changed | Notable behaviour |
|---|---|---|---|
| P6 JAR | `ad3476ee` | Server: `EnableRequestObjectSupport()`, `RequireSignedRequestObjects()`, per-client `ft:jar`, discovery metadata. Client: `UseSignedRequestObjects`. | Parameters outside the object are ignored (RFC 9101). Objects are validated with the client JWKS. |
| P8 CIBA (server) | `30193eb8` | Backchannel endpoint and pass-through, `urn:openid:params:grant-type:ciba`, `OpenIddictServerService` (list / approve / reject), discovery metadata. | Requires `SetIssuer`, token storage and non-degraded mode. **Device flow now returns `interval` and enforces `slow_down`**; disable with `SetPollingInterval(null)`. |

Tests pass on every run: server unit tests (686), ASP.NET Core integration (1,529), OWIN integration (1,499), abstractions (1,451), client (149).

## 5. Remaining work (ordered)

| # | Phase | Size | Dependency / risk |
|---|---|---|---|
| 1 | P8b CIBA client | M | — |
| 2 | P10 key management | L | New Key entity (schema change); refactor of all credential reads |
| 3 | P5 DPoP | L | One DB write per protected request for replay protection; proxy `htu` normalization |
| 4 | P12 JWT introspection | S | — |
| 5 | P11.2 dynamic providers | M | Client registration lifecycle refactor |
| 6 | P11.3 BFF | M | YARP dependency (approved) |
| 7 | P11.4 / P11.5 templates, admin API | M | New template pack (approved) |
| 8 | P11.6 SAML | XL | New package; XML signature attack surface |
| — | P1, P2, P4, P9, P11.1 | L | Blocked until upstream `8.0.0-preview.5` is merged |

## 6. Risks

- **Divergence from upstream:** keep fork-only features isolated per branch; rebase when preview.5 ships.
- **Schema changes** (sessions, keys, provider registrations): batch them into one preview.
- **Behaviour change** in device-flow polling: needs a release note.
- **Scope:** every phase is independently shippable, and P11.4–P11.6 can be dropped.
