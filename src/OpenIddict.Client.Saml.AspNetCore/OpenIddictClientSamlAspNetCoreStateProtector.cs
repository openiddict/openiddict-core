/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Buffers.Text;
using System.Security.Cryptography;
using Microsoft.AspNetCore.DataProtection;
using static OpenIddict.Client.Saml.OpenIddictClientSamlModels;

namespace OpenIddict.Client.Saml.AspNetCore;

/// <summary>
/// Protects the state of pending SAML authentication requests stored in correlation cookies.
/// </summary>
/// <remarks>
/// The expiration date, the request identifier and the relay state are part of the protected payload
/// and are enforced by <see cref="OpenIddictClientSamlService.ValidateResponseAsync"/>.
/// </remarks>
public sealed class OpenIddictClientSamlAspNetCoreStateProtector
{
    private readonly IDataProtector _protector;

    /// <summary>
    /// Creates a new instance of the <see cref="OpenIddictClientSamlAspNetCoreStateProtector"/> class.
    /// </summary>
    /// <param name="provider">The data protection provider.</param>
    public OpenIddictClientSamlAspNetCoreStateProtector(IDataProtectionProvider provider)
    {
        ArgumentNullException.ThrowIfNull(provider);

        _protector = provider.CreateProtector("OpenIddict.Client.Saml.AspNetCore.RequestState.v1");
    }

    /// <summary>
    /// Protects the specified state.
    /// </summary>
    /// <param name="state">The state.</param>
    /// <returns>The protected state, encoded using base64url.</returns>
    public string Protect(RequestState state)
    {
        ArgumentNullException.ThrowIfNull(state);

        return Base64Url.EncodeToString(_protector.Protect(OpenIddictClientSamlService.SerializeRequestState(state)));
    }

    /// <summary>
    /// Unprotects the specified state.
    /// </summary>
    /// <param name="value">The protected state.</param>
    /// <returns>The state, or <see langword="null"/> if it is invalid.</returns>
    public RequestState? Unprotect(string? value)
    {
        if (string.IsNullOrEmpty(value))
        {
            return null;
        }

        try
        {
            return OpenIddictClientSamlService.DeserializeRequestState(_protector.Unprotect(Base64Url.DecodeFromChars(value)));
        }

        catch (Exception exception) when (exception is CryptographicException or FormatException)
        {
            return null;
        }
    }
}
