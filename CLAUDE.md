# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

OpenIddict is an open-source framework for building OAuth 2.0/OpenID Connect servers and clients in .NET. It provides a modular architecture with pluggable stores (EF Core, EF 6.x, MongoDB) and host integrations (ASP.NET Core, OWIN).

## Build Commands

The project uses Microsoft.DotNet.Arcade.Sdk with .NET SDK 10.0.

```bash
# Build (Windows)
Build.cmd

# Build (Unix/macOS)
./build.sh

# Full CI build with tests
# Windows:
eng\common\Build.cmd -restore -build -test
# Unix:
./eng/common/build.sh -restore -build -test

# Build specific project
dotnet build src/OpenIddict.Core/OpenIddict.Core.csproj

# Run all tests
dotnet test

# Run a single test project
dotnet test test/OpenIddict.Core.Tests/OpenIddict.Core.Tests.csproj

# Run a single test by name
dotnet test test/OpenIddict.Core.Tests/OpenIddict.Core.Tests.csproj --filter "FullyQualifiedName~MyTestMethod"

# Full CI build (restore, build, test, sign, pack)
eng\common\Build.cmd -configuration Release -ci -prepareMachine -restore -build -test -sign -pack
```

## Multi-Targeting

Projects target many frameworks simultaneously: net462, net472, net48, netstandard2.0, netstandard2.1, net8.0, net9.0, net10.0, plus mobile platforms (Android, iOS, macOS, Mac Catalyst, Windows) when workloads are available.

Conditional compilation uses `SUPPORTS_*` defines (e.g., `SUPPORTS_KEY_DERIVATION_WITH_SPECIFIED_HASH_ALGORITHM`, `SUPPORTS_CERTIFICATE_LOADER`) set in `Directory.Build.targets`. Use `#if` directives for platform-specific code paths.

## Architecture

### Core Abstraction Layers

1. **OpenIddict.Abstractions** — Interfaces, constants, descriptors, store contracts, and primitive types. Everything depends on this.
2. **OpenIddict.Core** — Generic managers (`OpenIddictApplicationManager<T>`, `OpenIddictAuthorizationManager<T>`, `OpenIddictScopeManager<T>`, `OpenIddictTokenManager<T>`) and caches. Managers coordinate stores, caches, validation, and business logic.
3. **OpenIddict.Server / .Client / .Validation** — Protocol implementations using an event-driven handler/filter/dispatcher pattern.

### Store Pattern

Store interfaces (`IOpenIddictApplicationStore<T>`, etc.) abstract persistence. Implementations:
- `OpenIddict.EntityFrameworkCore` — EF Core stores
- `OpenIddict.EntityFramework` — EF 6.x stores
- `OpenIddict.MongoDb` — MongoDB stores
- Corresponding `.Models` projects hold entity classes

### Host Integration Pattern

Each protocol component (Server, Client, Validation) has host-specific projects:
- `.AspNetCore` — ASP.NET Core middleware integration
- `.Owin` — OWIN/Katana integration for ASP.NET 4.x
- `.DataProtection` — ASP.NET Core Data Protection token formats

### Handler/Filter Pattern

Request processing uses event handlers guarded by filters. Handlers are registered via `IOpenIddictServerHandlers`, and filters (e.g., `RequireAccessTokenGenerated`, `RequireClientIdParameter`) control execution flow.

### DI Registration

Builder pattern via `OpenIddictBuilder` with extension methods in `Microsoft.Extensions.DependencyInjection` namespace. Uses `TryAddScoped`/`TryAddSingleton` for idempotent registration.

## Code Conventions

- C# 14, nullable reference types enabled, implicit usings enabled (`Directory.Build.props`)
- `TreatWarningsAsErrors: true`
- File-scoped namespaces throughout
- `ValueTask` for async manager methods; `CancellationToken` on all async APIs
- `SR.GetResourceString()` for localized exception messages (resource strings in Abstractions)
- Strong-name signed assemblies (key at `eng/key.snk`)
- CRLF line endings, 4-space indentation (enforced via `.editorconfig`)

## Testing

- xUnit with Moq
- Test projects mirror source projects under `/test/` (e.g., `OpenIddict.Core.Tests`)
- Integration tests in `*.IntegrationTests` projects
- `[Fact]` for deterministic tests, `[Theory]` + `[InlineData]` for parameterized tests
- CI runs tests on Windows, Ubuntu, and macOS

## Key Directories

- `/eng/` — Arcade build infrastructure, signing key
- `/gen/` — Code generators (Client WebIntegration provider generator)
- `/src/` — Source libraries (~30 projects)
- `/test/` — Test projects (~18 projects)
- `/sandbox/` — Sample/reference applications
- `/shared/OpenIddict.Extensions/` — Shared helper utilities and polyfills
