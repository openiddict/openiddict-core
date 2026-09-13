/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

namespace OpenIddict.Client.AspNetCore.Bff;

/// <summary>
/// Represents the endpoint metadata marking a local endpoint as a BFF API endpoint: requests
/// must contain the antiforgery header and unauthenticated calls receive 401 responses
/// instead of being redirected to the login page.
/// </summary>
public sealed class OpenIddictClientAspNetCoreBffApiEndpointMetadata
{
    /// <summary>
    /// Gets or sets a boolean indicating whether the antiforgery header check is disabled.
    /// </summary>
    public bool DisableAntiforgeryCheck { get; init; }
}
