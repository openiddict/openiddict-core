/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using OpenIddict.Client.Saml.AspNetCore;
using static OpenIddict.Client.Saml.OpenIddictClientSamlModels;

namespace Microsoft.AspNetCore;

/// <summary>
/// Exposes companion extensions for the OpenIddict SAML service provider ASP.NET Core integration.
/// </summary>
public static class OpenIddictClientSamlAspNetCoreHelpers
{
    /// <summary>
    /// Retrieves the validation result of the SAML response received by the assertion consumer service, if applicable.
    /// </summary>
    /// <param name="context">The <see cref="HttpContext"/> instance.</param>
    /// <returns>The validation result, or <see langword="null"/> if no SAML response was validated.</returns>
    public static ResponseValidationResult? GetOpenIddictClientSamlResponse(this HttpContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        return context.Features.Get<OpenIddictClientSamlAspNetCoreFeature>()?.Result;
    }
}
