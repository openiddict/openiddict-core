/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using Properties = OpenIddict.Client.WebIntegration.OpenIddictClientWebIntegrationConstants.Properties;

namespace OpenIddict.Client.WebIntegration;

/// <summary>
/// Exposes companion extensions for the OpenIddict client Web integration.
/// </summary>
public static class OpenIddictClientWebIntegrationHelpers
{
    public static string? GetProviderName(this OpenIddictClientRegistration registration!!)
        => registration.Properties.TryGetValue(Properties.ProviderName, out var provider)
            && provider is string value ? value : null;
}
