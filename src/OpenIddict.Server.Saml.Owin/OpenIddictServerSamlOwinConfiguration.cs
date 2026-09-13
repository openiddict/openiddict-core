/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.ComponentModel;
using Microsoft.Extensions.Options;

namespace OpenIddict.Server.Saml.Owin;

/// <summary>
/// Contains the methods required to ensure that the OpenIddict SAML OWIN/Katana configuration is valid.
/// </summary>
[EditorBrowsable(EditorBrowsableState.Advanced)]
public sealed class OpenIddictServerSamlOwinConfiguration : IValidateOptions<OpenIddictServerSamlOwinOptions>
{
    /// <inheritdoc/>
    public ValidateOptionsResult Validate(string? name, OpenIddictServerSamlOwinOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);

        if (string.IsNullOrEmpty(options.AuthenticationType))
        {
            return ValidateOptionsResult.Fail(SR.GetResourceString(SR.ID0579));
        }

        if (options.RequestStateLifetime <= TimeSpan.Zero)
        {
            return ValidateOptionsResult.Fail(SR.GetResourceString(SR.ID0572));
        }

        return ValidateOptionsResult.Success;
    }
}
