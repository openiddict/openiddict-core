/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using static OpenIddict.Client.Saml.OpenIddictClientSamlModels;

namespace OpenIddict.Client.Saml.AspNetCore;

/// <summary>
/// Exposes the result of the validation of the SAML response received by the assertion consumer service.
/// </summary>
public sealed class OpenIddictClientSamlAspNetCoreFeature
{
    /// <summary>
    /// Gets or sets the validation result of the SAML response, if applicable.
    /// </summary>
    public ResponseValidationResult? Result { get; set; }
}
