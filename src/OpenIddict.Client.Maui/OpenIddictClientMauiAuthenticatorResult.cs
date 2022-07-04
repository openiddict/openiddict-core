/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Security.Claims;

namespace OpenIddict.Client.Maui;

/// <summary>
/// Represents a succesful authentication result returned by the OpenIddict client.
/// </summary>
public class OpenIddictClientMauiAuthenticatorResult : WebAuthenticatorResult
{
    /// <summary>
    /// Creates a new instance of the <see cref="OpenIddictClientMauiAuthenticatorResult"/> class.
    /// </summary>
    /// <param name="principal">The merged principal resolved from the authentication response.</param>
    /// <param name="properties">The parameters resolved from the authentication response.</param>
    public OpenIddictClientMauiAuthenticatorResult(ClaimsPrincipal principal, IDictionary<string, string> properties)
        : base(properties)
        => Principal = principal ?? throw new ArgumentNullException(nameof(principal));

    /// <summary>
    /// Gets the merged principal resolved from the authentication response.
    /// </summary>
    public ClaimsPrincipal Principal { get; }
}
