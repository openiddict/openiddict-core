/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.ComponentModel;
using Microsoft.Extensions.Options;

namespace OpenIddict.Client.Saml.Owin;

/// <summary>
/// Contains the methods required to ensure that the OpenIddict SAML OWIN/Katana configuration is valid.
/// </summary>
[EditorBrowsable(EditorBrowsableState.Advanced)]
public sealed class OpenIddictClientSamlOwinConfiguration : IValidateOptions<OpenIddictClientSamlOwinOptions>
{
    /// <inheritdoc/>
    public ValidateOptionsResult Validate(string? name, OpenIddictClientSamlOwinOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);

        if (string.IsNullOrEmpty(options.AuthenticationType) ||
           (!options.EnableAssertionConsumerServicePassthrough && string.IsNullOrEmpty(options.SignInAuthenticationType)))
        {
            return ValidateOptionsResult.Fail(SR.GetResourceString(SR.ID0902));
        }

        if (!options.AssertionConsumerServicePath.HasValue || !options.MetadataPath.HasValue ||
            options.AssertionConsumerServicePath == options.MetadataPath)
        {
            return ValidateOptionsResult.Fail(SR.GetResourceString(SR.ID0906));
        }

        if (string.IsNullOrEmpty(options.CorrelationCookieName))
        {
            return ValidateOptionsResult.Fail(SR.GetResourceString(SR.ID0911));
        }

        return ValidateOptionsResult.Success;
    }
}
