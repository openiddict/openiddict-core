using OpenIddict.Abstractions;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace Company.Server;

/// <summary>
/// Represents a client application declared in the "OpenIddict:Clients" configuration section.
/// </summary>
public sealed class ClientDefinition
{
    public string ClientId { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the client secret. Clients without a secret are registered as public clients.
    /// </summary>
    public string? ClientSecret { get; set; }

    public string? DisplayName { get; set; }

    public string ConsentType { get; set; } = ConsentTypes.Explicit;

    public List<string> GrantTypes { get; set; } = [];

    public List<string> Scopes { get; set; } = [];

    public List<Uri> RedirectUris { get; set; } = [];

    public List<Uri> PostLogoutRedirectUris { get; set; } = [];

    /// <summary>
    /// Creates the application descriptor corresponding to this client definition.
    /// </summary>
    public OpenIddictApplicationDescriptor CreateDescriptor()
    {
        var descriptor = new OpenIddictApplicationDescriptor
        {
            ClientId = ClientId,
            ClientSecret = ClientSecret,
            ClientType = string.IsNullOrEmpty(ClientSecret) ? ClientTypes.Public : ClientTypes.Confidential,
            ConsentType = ConsentType,
            DisplayName = DisplayName ?? ClientId,
            Permissions = { Permissions.Endpoints.Token }
        };

        descriptor.RedirectUris.UnionWith(RedirectUris);
        descriptor.PostLogoutRedirectUris.UnionWith(PostLogoutRedirectUris);

        if (descriptor.ClientType is ClientTypes.Confidential)
        {
            descriptor.Permissions.Add(Permissions.Endpoints.Introspection);
            descriptor.Permissions.Add(Permissions.Endpoints.Revocation);
        }

        foreach (var type in GrantTypes)
        {
            descriptor.AddGrantTypePermissions(type);

            switch (type)
            {
                case OpenIddictConstants.GrantTypes.AuthorizationCode:
                    descriptor.Permissions.Add(Permissions.Endpoints.Authorization);
                    descriptor.Permissions.Add(Permissions.Endpoints.EndSession);
                    descriptor.Permissions.Add(Permissions.ResponseTypes.Code);
                    descriptor.Requirements.Add(Requirements.Features.ProofKeyForCodeExchange);
                    break;

                case OpenIddictConstants.GrantTypes.DeviceCode:
                    descriptor.Permissions.Add(Permissions.Endpoints.DeviceAuthorization);
                    break;
            }
        }

        descriptor.AddScopePermissions([.. Scopes]);

        return descriptor;
    }
}
