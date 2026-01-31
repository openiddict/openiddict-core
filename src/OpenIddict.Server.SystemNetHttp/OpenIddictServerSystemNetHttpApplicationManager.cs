/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Collections.Immutable;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using OpenIddict.Core;

namespace OpenIddict.Server.SystemNetHttp;

/// <summary>
/// A CIMD-aware application manager that synthesizes virtual applications from
/// Client ID Metadata Documents. When <c>FindByClientIdAsync</c> returns null
/// from the underlying store and a CIMD metadata document has been fetched for
/// the current request, this manager returns a synthesized virtual application
/// populated with the metadata from the document.
/// </summary>
/// <typeparam name="TApplication">The type of the Application entity.</typeparam>
public class OpenIddictServerSystemNetHttpApplicationManager<TApplication>
    : OpenIddictApplicationManager<TApplication> where TApplication : class
{
    private readonly OpenIddictServerSystemNetHttpCimdContext _cimdContext;

    public OpenIddictServerSystemNetHttpApplicationManager(
        IOpenIddictApplicationCache<TApplication> cache,
        ILogger<OpenIddictApplicationManager<TApplication>> logger,
        IOptionsMonitor<OpenIddictCoreOptions> options,
        IOpenIddictApplicationStore<TApplication> store,
        OpenIddictServerSystemNetHttpCimdContext cimdContext)
        : base(cache, logger, options, store)
    {
        _cimdContext = cimdContext ?? throw new ArgumentNullException(nameof(cimdContext));
    }

    /// <inheritdoc/>
    public override async ValueTask<TApplication?> FindByClientIdAsync(
        string identifier, CancellationToken cancellationToken = default)
    {
        // First, try the base implementation (pre-registered clients always win).
        var application = await base.FindByClientIdAsync(identifier, cancellationToken);
        if (application is not null)
        {
            return application;
        }

        // If the base returned null, check if we have a CIMD context for this client_id.
        if (!string.Equals(_cimdContext.ClientId, identifier, StringComparison.Ordinal) ||
            _cimdContext.MetadataDocument is null)
        {
            return null;
        }

        // Return cached virtual application if already synthesized.
        if (_cimdContext.VirtualApplication is TApplication cached)
        {
            return cached;
        }

        // Synthesize a virtual application from the CIMD metadata document.
        var virtualApp = await SynthesizeVirtualApplicationAsync(
            identifier, _cimdContext.MetadataDocument, cancellationToken);

        _cimdContext.VirtualApplication = virtualApp;

        return virtualApp;
    }

    /// <inheritdoc/>
    public override ValueTask<string?> GetIdAsync(
        TApplication application, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(application);

        // Virtual applications have no database identity.
        if (ReferenceEquals(application, _cimdContext.VirtualApplication))
        {
            return new ValueTask<string?>((string?) null);
        }

        return base.GetIdAsync(application, cancellationToken);
    }

    private async ValueTask<TApplication> SynthesizeVirtualApplicationAsync(
        string clientId, JsonDocument document, CancellationToken cancellationToken)
    {
        var application = await Store.InstantiateAsync(cancellationToken);

        await Store.SetClientIdAsync(application, clientId, cancellationToken);
        await Store.SetClientTypeAsync(application, ClientTypes.Public, cancellationToken);

        // Set application type from metadata, defaulting to "web".
        var applicationType = ApplicationTypes.Web;
        if (document.RootElement.TryGetProperty("application_type", out var appTypeElement) &&
            appTypeElement.ValueKind == JsonValueKind.String)
        {
            applicationType = appTypeElement.GetString() ?? ApplicationTypes.Web;
        }
        await Store.SetApplicationTypeAsync(application, applicationType, cancellationToken);

        // Set display name from metadata if present.
        if (document.RootElement.TryGetProperty("client_name", out var clientNameElement) &&
            clientNameElement.ValueKind == JsonValueKind.String)
        {
            await Store.SetDisplayNameAsync(application, clientNameElement.GetString(), cancellationToken);
        }

        // Set redirect URIs from metadata.
        var redirectUris = ImmutableArray.CreateBuilder<string>();
        if (document.RootElement.TryGetProperty("redirect_uris", out var redirectUrisElement) &&
            redirectUrisElement.ValueKind == JsonValueKind.Array)
        {
            foreach (var element in redirectUrisElement.EnumerateArray())
            {
                if (element.ValueKind == JsonValueKind.String)
                {
                    var uri = element.GetString();
                    if (!string.IsNullOrEmpty(uri))
                    {
                        redirectUris.Add(uri);
                    }
                }
            }
        }
        await Store.SetRedirectUrisAsync(application, redirectUris.ToImmutable(), cancellationToken);

        // Build permissions: grant all standard endpoint, grant_type, response_type,
        // and scope permissions since CIMD clients aren't permission-restricted.
        var permissions = ImmutableArray.CreateBuilder<string>();

        // Endpoint permissions.
        permissions.Add(Permissions.Endpoints.Authorization);
        permissions.Add(Permissions.Endpoints.Token);

        // Grant type permissions from metadata.
        if (document.RootElement.TryGetProperty("grant_types", out var grantTypesElement) &&
            grantTypesElement.ValueKind == JsonValueKind.Array)
        {
            foreach (var element in grantTypesElement.EnumerateArray())
            {
                if (element.ValueKind == JsonValueKind.String)
                {
                    var grantType = element.GetString();
                    var permission = grantType switch
                    {
                        GrantTypes.AuthorizationCode => Permissions.GrantTypes.AuthorizationCode,
                        GrantTypes.Implicit          => Permissions.GrantTypes.Implicit,
                        GrantTypes.RefreshToken       => Permissions.GrantTypes.RefreshToken,
                        GrantTypes.DeviceCode         => Permissions.GrantTypes.DeviceCode,
                        GrantTypes.ClientCredentials  => Permissions.GrantTypes.ClientCredentials,
                        GrantTypes.TokenExchange      => Permissions.GrantTypes.TokenExchange,
                        GrantTypes.Password           => Permissions.GrantTypes.Password,
                        _ => null
                    };

                    if (permission is not null && !permissions.Contains(permission))
                    {
                        permissions.Add(permission);
                    }
                }
            }
        }
        else
        {
            // Default grant type if not specified.
            permissions.Add(Permissions.GrantTypes.AuthorizationCode);
        }

        // Response type permissions from metadata.
        if (document.RootElement.TryGetProperty("response_types", out var responseTypesElement) &&
            responseTypesElement.ValueKind == JsonValueKind.Array)
        {
            foreach (var element in responseTypesElement.EnumerateArray())
            {
                if (element.ValueKind == JsonValueKind.String)
                {
                    var responseType = element.GetString();
                    var permission = responseType switch
                    {
                        ResponseTypes.Code                           => Permissions.ResponseTypes.Code,
                        "code id_token"                              => Permissions.ResponseTypes.CodeIdToken,
                        "code id_token token"                        => Permissions.ResponseTypes.CodeIdTokenToken,
                        "code token"                                 => Permissions.ResponseTypes.CodeToken,
                        "id_token"                                   => Permissions.ResponseTypes.IdToken,
                        "id_token token"                             => Permissions.ResponseTypes.IdTokenToken,
                        "none"                                       => Permissions.ResponseTypes.None,
                        "token"                                      => Permissions.ResponseTypes.Token,
                        _ => null
                    };

                    if (permission is not null && !permissions.Contains(permission))
                    {
                        permissions.Add(permission);
                    }
                }
            }
        }
        else
        {
            // Default response type if not specified.
            permissions.Add(Permissions.ResponseTypes.Code);
        }

        // Add common scope permissions.
        permissions.Add(Permissions.Scopes.Email);
        permissions.Add(Permissions.Scopes.Profile);
        permissions.Add(Permissions.Scopes.Address);
        permissions.Add(Permissions.Scopes.Phone);
        permissions.Add(Permissions.Scopes.Roles);

        await Store.SetPermissionsAsync(application, permissions.ToImmutable(), cancellationToken);

        // Set requirements: PKCE is always required for CIMD clients.
        await Store.SetRequirementsAsync(application,
            [Requirements.Features.ProofKeyForCodeExchange], cancellationToken);

        // Use empty settings (server defaults apply).
        await Store.SetSettingsAsync(application, ImmutableDictionary<string, string>.Empty, cancellationToken);

        return application;
    }
}
