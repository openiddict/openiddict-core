# OpenIddict templates

`dotnet new` template pack (`OpenIddict.Templates`).

| Short name | Folder | Content |
|---|---|---|
| `openiddict-server-identity` | `content/OpenIddict.Server.Identity` | ASP.NET Core Identity (default UI) + EF Core SQLite; MVC authorization/consent, device verification, end session, token (code, device, refresh, client credentials), userinfo; clients seeded from `OpenIddict:Clients`; optional admin API (`OpenIddict:EnableAdminApi`, role `OpenIddict:AdminRole`) |
| `openiddict-server-empty` | `content/OpenIddict.Server.Empty` | Minimal APIs + EF Core SQLite; pass-through authorization/token/end session/userinfo; cookie login placeholder (development only, returns 501 otherwise) |
| `openiddict-bff` | `content/OpenIddict.Bff` | OpenIddict client + `OpenIddict.Client.AspNetCore.Bff` (session endpoints, refresh, antiforgery, in-memory session store) + YARP routes from `ReverseProxy` |

## Parameters

| Parameter | Templates | Default |
|---|---|---|
| `--OpenIddictVersion` | all | `8.0.0-preview.5` (pack fails if it differs from `eng/Versions.props`) |
| `--admin-ui` | `openiddict-server-identity` | `false` (maps `OpenIddict.Server.AspNetCore.AdminUI` under `/admin`, policy `admin`) |
| `--Authority`, `--ClientId` | `openiddict-bff` | `https://localhost:44310/`, `bff` |

## Usage

```sh
dotnet new install templates/content/OpenIddict.Server.Identity   # or the packed OpenIddict.Templates nupkg
dotnet new openiddict-server-identity -n MyServer
```

## Verification

`templates/verify.sh` packs the required `src` packages into a temporary feed, instantiates each template, builds it and runs HTTP smoke tests (code flow end to end for both servers, BFF anonymous checks). Requires bash, curl, openssl, python and a trusted ASP.NET Core development certificate.

## Notes

- `content/Directory.*.props|targets` isolate the template sources from the repository build; they are not packed.
- Development signing/encryption certificates must be replaced in production.
