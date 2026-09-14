/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

namespace OpenIddict.Server.SystemNetHttp;

/// <summary>
/// Exposes common constants used by the OpenIddict server/System.Net.Http integration.
/// </summary>
public static class OpenIddictServerSystemNetHttpConstants
{
    /// <summary>
    /// Gets the name of the <see cref="System.Net.Http.HttpClient"/> used to send back-channel logout requests.
    /// It can be configured using <c>services.AddHttpClient(OpenIddictServerSystemNetHttpConstants.HttpClientName)</c>.
    /// </summary>
    public const string HttpClientName = "OpenIddict.Server.SystemNetHttp";
}
