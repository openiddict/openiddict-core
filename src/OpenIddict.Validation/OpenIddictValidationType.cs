/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

namespace OpenIddict.Validation;

/// <summary>
/// Represents the type of validation performed by the OpenIddict validation services.
/// </summary>
public enum OpenIddictValidationType
{
    /// <summary>
    /// Configures the OpenIddict validation services to use direct validation.
    /// By default, direct validation uses IdentityModel to validate JWT tokens,
    /// but a different token format can be used by registering the corresponding
    /// package (e.g OpenIddict.Validation.DataProtection, for Data Protection tokens).
    /// </summary>
    Direct = 0,

    /// <summary>
    /// Configures the OpenIddict validation services to use introspection.
    /// When using introspection, an OAuth 2.0 introspection request is sent
    /// to the authorization server to validate the received access token.
    /// </summary>
    Introspection = 1
}
