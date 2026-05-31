/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.ComponentModel;
using Microsoft.Extensions.Options;

namespace OpenIddict.Validation.AspNetCore;

/// <summary>
/// Contains the methods required to ensure that the OpenIddict validation configuration is valid.
/// </summary>
[EditorBrowsable(EditorBrowsableState.Advanced)]
public sealed class OpenIddictValidationAspNetCoreConfiguration : IConfigureOptions<AuthenticationOptions>,
                                                                  IConfigureOptions<OpenIddictValidationOptions>,
                                                                  IPostConfigureOptions<AuthenticationOptions>,
                                                                  IValidateOptions<AuthenticationOptions>
{
    /// <inheritdoc/>
    public void Configure(AuthenticationOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);

        // Register the authentication scheme handler used by the OpenIddict ASP.NET Core server integration.
        if (!options.SchemeMap.ContainsKey(OpenIddictValidationAspNetCoreDefaults.AuthenticationScheme))
        {
            options.AddScheme<OpenIddictValidationAspNetCoreHandler>(
                OpenIddictValidationAspNetCoreDefaults.AuthenticationScheme, displayName: null);
        }
    }

    /// <inheritdoc/>
    public void Configure(OpenIddictValidationOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);

        // Register the built-in event handlers used by the OpenIddict ASP.NET Core validation components.
        options.Handlers.AddRange(OpenIddictValidationAspNetCoreHandlers.DefaultHandlers);
    }

    /// <inheritdoc/>
    public void PostConfigure(string? name, AuthenticationOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);

        // Starting in ASP.NET 7.0, the authentication stack integrates a fallback
        // mechanism to select the default scheme to use when no value is set, but
        // only if a single handler has been registered in the authentication options.
        //
        // Unfortunately, this behavior is problematic for OpenIddict as it enforces
        // strict checks to prevent calling certain unsafe authentication operations
        // on invalid endpoints. To opt out this undesirable behavior, a fake entry
        // is dynamically added if one of the default schemes properties is not set
        // and less than 2 handlers were registered in the authentication options.
        if (options.SchemeMap.Count is < 2 && string.IsNullOrEmpty(options.DefaultScheme) &&
           (string.IsNullOrEmpty(options.DefaultSignInScheme) ||
            string.IsNullOrEmpty(options.DefaultSignOutScheme)))
        {
            options.AddScheme<IAuthenticationHandler>(Guid.NewGuid().ToString(), displayName: null);
        }
    }

    /// <inheritdoc/>
    public ValidateOptionsResult Validate(string? name, AuthenticationOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);

        var builder = new ValidateOptionsResultBuilder();

        if (!ValidateDefaultScheme(options.SchemeMap, options.DefaultSignInScheme) ||
            !ValidateDefaultScheme(options.SchemeMap, options.DefaultSignOutScheme))
        {
            builder.AddError(SR.GetResourceString(SR.ID0165));
        }

        return builder.Build();

        static bool ValidateDefaultScheme(IDictionary<string, AuthenticationSchemeBuilder> map, string? scheme)
        {
            // If the scheme was not set or if it cannot be found in the map, return true.
            if (string.IsNullOrEmpty(scheme) || !map.TryGetValue(scheme, out var builder))
            {
                return true;
            }

            return builder.HandlerType != typeof(OpenIddictValidationAspNetCoreHandler);
        }
    }
}
