/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.ComponentModel;
using Microsoft.Extensions.Options;

namespace OpenIddict.Client.Saml.AspNetCore;

/// <summary>
/// Contains the methods required to ensure that the OpenIddict SAML ASP.NET Core configuration is valid.
/// </summary>
[EditorBrowsable(EditorBrowsableState.Advanced)]
public sealed class OpenIddictClientSamlAspNetCoreConfiguration : IConfigureOptions<AuthenticationOptions>,
                                                                  IValidateOptions<OpenIddictClientSamlAspNetCoreOptions>
{
    /// <inheritdoc/>
    public void Configure(AuthenticationOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);

        // Register the authentication handler used by the OpenIddict SAML ASP.NET Core integration.
        if (!options.SchemeMap.ContainsKey(OpenIddictClientSamlAspNetCoreDefaults.AuthenticationScheme))
        {
            options.AddScheme<OpenIddictClientSamlAspNetCoreHandler>(
                OpenIddictClientSamlAspNetCoreDefaults.AuthenticationScheme, displayName: null);
        }
    }

    /// <inheritdoc/>
    public ValidateOptionsResult Validate(string? name, OpenIddictClientSamlAspNetCoreOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);

        if (!options.AssertionConsumerServicePath.HasValue || !options.MetadataPath.HasValue ||
            options.AssertionConsumerServicePath == options.MetadataPath)
        {
            return ValidateOptionsResult.Fail(SR.GetResourceString(SR.ID0906));
        }

        if (options.CorrelationCookie is null || string.IsNullOrEmpty(options.CorrelationCookie.Name))
        {
            return ValidateOptionsResult.Fail(SR.GetResourceString(SR.ID0911));
        }

        return ValidateOptionsResult.Success;
    }
}
