# Client ID Metadata Document (CIMD) Support

Implements [draft-ietf-oauth-client-id-metadata-document](https://datatracker.ietf.org/doc/draft-ietf-oauth-client-id-metadata-document/) for OpenIddict, enabling dynamic client registration via HTTPS URLs. This is a foundational building block for **MCP (Model Context Protocol) authentication**, where AI tool servers identify themselves using metadata document URLs rather than pre-registered client credentials.

## Purpose

Traditional OAuth 2.0 requires clients to be pre-registered with the authorization server. CIMD removes this requirement: a client presents an HTTPS URL as its `client_id`, and the server fetches a JSON metadata document from that URL to learn the client's capabilities. This enables:

- **MCP authentication** — AI agents and tool servers can authenticate without manual client registration
- **Decentralized client identity** — clients self-publish their metadata at a URL they control
- **Zero-touch onboarding** — new clients work immediately without admin intervention

## Design and Architecture

CIMD integrates into OpenIddict's existing handler/filter pipeline and is disabled by default (opt-in via `EnableClientIdMetadataDocumentSupport()`).

### Request Flow

```
1. Client sends request with client_id=https://example.com/client
2. ValidateClientId checks the application store — not found
3. ValidateClientId detects valid HTTPS URL, sets fetch-required flag
4. FetchClientIdMetadataDocument handler fetches the URL, validates the JSON
5. Metadata stored in scoped CimdContext for the request lifetime
6. Application manager synthesizes a virtual application from metadata
7. Pipeline continues with the virtual app as if it were pre-registered
```

### New Project: `OpenIddict.Server.SystemNetHttp`

| Component | Role |
|---|---|
| `OpenIddictServerSystemNetHttpApplicationManager` | Overrides `FindByClientIdAsync` — returns pre-registered apps first, synthesizes virtual apps from CIMD context when none found |
| `OpenIddictServerSystemNetHttpCimdContext` | Scoped request state holding the fetched metadata and cached virtual application |
| `FetchClientIdMetadataDocument` handler | Runs in `ProcessAuthenticationContext` (applies to authorize, token, and all endpoints); fetches, validates, and stores metadata |
| `RequireClientIdMetadataDocumentSupportEnabled` filter | Gates all CIMD handlers on the opt-in flag |

### Modified Server Components

- **`ValidateClientId`** — flags unknown HTTPS URL client IDs for metadata fetch instead of rejecting them
- **`ValidateClientType`** — skips type validation for CIMD clients; rejects if a client secret is provided
- **Discovery metadata** — advertises `client_id_metadata_document_supported: true` when enabled

### Virtual Application Synthesis

When the metadata document is fetched, a virtual application is synthesized with the following mapping:

| Metadata Field | Application Property | Rules |
|---|---|---|
| `client_id` | ClientId | Required, must match the URL |
| N/A | ClientType | Always `Public` |
| `application_type` | ApplicationType | Defaults to `Web` if absent |
| `client_name` | DisplayName | Optional |
| `redirect_uris` | RedirectUris | Optional, validated against during authorization |
| `grant_types` | Permissions | Mapped to `Permissions.GrantTypes.*` |
| `response_types` | Permissions | Mapped to `Permissions.ResponseTypes.*` |
| N/A | Requirements | Always includes PKCE |
| N/A | Permissions | Includes authorization endpoint, token endpoint, and common scopes (email, profile, address, phone, roles) |

## Design Choices

**Synthetic (virtual) applications.** When the CIMD metadata is fetched, a virtual `OpenIddictApplication` object is synthesized in memory. This avoids writing to the database and means CIMD clients leave no persistent footprint. Pre-registered applications always take priority — the store is checked first, and CIMD only kicks in for unknown client IDs.

**Always public, always PKCE.** CIMD clients are forced to be public clients (no client secret) and must use PKCE. This is a deliberate security constraint: there is no secure way to distribute a shared secret via a publicly-fetchable metadata document. PKCE protects the authorization code flow without needing a secret.

**Fetch in `ProcessAuthenticationContext`.** The metadata fetch handler runs at the `ProcessAuthenticationContext` level rather than only during authorization. This ensures the metadata is available for all endpoint types — critically including the token endpoint during authorization code exchange and refresh token grants.

**Scoped context for request isolation.** The fetched metadata and synthesized virtual app are stored in a scoped `CimdContext`, ensuring concurrent requests don't interfere with each other. The virtual app is cached within the scope to avoid re-synthesis on repeated `FindByClientIdAsync` calls within the same request.

**No authorization records for virtual apps.** Since virtual applications have no database identity (`GetIdAsync` returns null), the authorization controller skips creating authorization entries for CIMD clients. This avoids foreign key issues and keeps the database clean.

**Metadata validation.** The fetched document is validated for: HTTPS scheme, no fragment or userinfo in URL, non-root path, `client_id` field matches the URL, forbidden auth methods rejected (`client_secret_post`, `client_secret_basic`, `client_secret_jwt`), size limit (5 KB default), and fetch timeout (10 seconds default).

## Configuration

```csharp
services.AddOpenIddict()
    .AddServer(options =>
    {
        options.EnableClientIdMetadataDocumentSupport();
        options.UseSystemNetHttp();
    });
```

Options on `OpenIddictServerOptions`:

| Property | Default | Description |
|---|---|---|
| `EnableClientIdMetadataDocumentSupport` | `false` | Opt-in flag |
| `ClientIdMetadataDocumentSizeLimit` | 5,120 bytes | Max metadata document size |
| `ClientIdMetadataDocumentFetchTimeout` | 10 seconds | HTTP fetch timeout |
| `ClientIdMetadataDocumentDefaultCacheDuration` | 1 hour | Cache duration when no HTTP cache headers present |

## Manual Verification with Postman

### Prerequisites

1. Start the CIMD sandbox server:
   ```
   dotnet run --project sandbox/OpenIddict.Sandbox.AspNetCore.CimdServer
   ```
   The server runs on `https://localhost:7295`. A test user (`testuser` / `Pass123$`) is seeded automatically.

2. Verify the metadata document is served:
   ```
   GET https://localhost:7295/clients/cimd-test
   ```
   Expected response:
   ```json
   {
     "client_id": "https://localhost:7295/clients/cimd-test",
     "client_name": "CIMD Test Client",
     "redirect_uris": ["http://localhost/callback"],
     "grant_types": ["authorization_code", "refresh_token"],
     "response_types": ["code"],
     "token_endpoint_auth_method": "none"
   }
   ```

### Step 1 — Generate PKCE values

Generate a `code_verifier` (43–128 character random string) and its SHA-256 `code_challenge`. Postman can generate these automatically in the Authorization tab (OAuth 2.0 type, PKCE enabled), or use an online tool.

Example:
- `code_verifier`: `dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk`
- `code_challenge`: `E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM` (BASE64URL of SHA-256)

### Step 2 — Authorization request

Open in a browser (not Postman — this requires cookie-based login):

```
https://localhost:7295/connect/authorize?
  client_id=https://localhost:7295/clients/cimd-test
  &redirect_uri=http://localhost/callback
  &response_type=code
  &scope=openid profile email offline_access
  &code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM
  &code_challenge_method=S256
```

The sandbox auto-signs in the test user and auto-approves consent. You will be redirected to `http://localhost/callback?code=<AUTHORIZATION_CODE>`. Copy the `code` parameter from the URL.

### Step 3 — Token exchange (Postman)

```
POST https://localhost:7295/connect/token
Content-Type: application/x-www-form-urlencoded

grant_type=authorization_code
&code=<AUTHORIZATION_CODE>
&client_id=https://localhost:7295/clients/cimd-test
&redirect_uri=http://localhost/callback
&code_verifier=dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk
```

Expected response: JSON with `access_token`, `id_token`, `refresh_token`, `token_type`, `expires_in`.

### Step 4 — Refresh token (Postman)

```
POST https://localhost:7295/connect/token
Content-Type: application/x-www-form-urlencoded

grant_type=refresh_token
&refresh_token=<REFRESH_TOKEN>
&client_id=https://localhost:7295/clients/cimd-test
```

Expected response: new `access_token`, `id_token`, and `refresh_token`.

### Discovery verification

```
GET https://localhost:7295/.well-known/openid-configuration
```

Confirm the response includes `"client_id_metadata_document_supported": true`.

## Test Coverage

31 tests across 4 test files:

- **23 unit tests** — virtual app synthesis (client type, PKCE requirement, redirect URIs, grant types, response types, display name, application type, scope permissions), metadata validation (size, format, URL rules), caching, pre-registered priority
- **8 integration tests** — discovery metadata advertisement, CIMD disabled rejection, transaction flag behavior, URL validation (HTTPS required, no fragments, no userinfo, no root paths)
- **2 handler filter tests** — enabled/disabled gating
- **2 context tests** — property defaults and round-tripping
