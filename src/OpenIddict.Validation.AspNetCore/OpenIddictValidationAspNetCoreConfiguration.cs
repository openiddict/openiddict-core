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
                                                                  IPostConfigureOptions<AuthenticationOptions>
{
    /// <summary>
    /// Registers the OpenIddict validation handler in the global authentication options.
    /// </summary>
    /// <param name="options">The options instance to initialize.</param>
    public void Configure(AuthenticationOptions options)
    {
        if (options is null)
        {
            throw new ArgumentNullException(nameof(options));
        }

        // If a handler was already registered and the type doesn't correspond to the OpenIddict handler, throw an exception.
        if (options.SchemeMap.TryGetValue(OpenIddictValidationAspNetCoreDefaults.AuthenticationScheme, out var builder) &&
            builder.HandlerType != typeof(OpenIddictValidationAspNetCoreHandler))
        {
            throw new InvalidOperationException(SR.GetResourceString(SR.ID0164));
        }

        options.AddScheme<OpenIddictValidationAspNetCoreHandler>(
            OpenIddictValidationAspNetCoreDefaults.AuthenticationScheme, displayName: null);
    }

    public void Configure(OpenIddictValidationOptions options)
    {
        if (options is null)
        {
            throw new ArgumentNullException(nameof(options));
        }

        // Register the built-in event handlers used by the OpenIddict ASP.NET Core validation components.
        options.Handlers.AddRange(OpenIddictValidationAspNetCoreHandlers.DefaultHandlers);
    }

    /// <summary>
    /// Ensures that the authentication configuration is in a consistent and valid state.
    /// </summary>
    /// <param name="name">The name of the options instance to configure, if applicable.</param>
    /// <param name="options">The options instance to initialize.</param>
    public void PostConfigure(string? name, AuthenticationOptions options)
    {
        if (options is null)
        {
            throw new ArgumentNullException(nameof(options));
        }

        if (!TryValidate(options.SchemeMap, options.DefaultSignInScheme) ||
            !TryValidate(options.SchemeMap, options.DefaultSignOutScheme))
        {
            throw new InvalidOperationException(SR.GetResourceString(SR.ID0165));
        }

#if SUPPORTS_AUTHENTICATION_HANDLER_SELECTION_FALLBACK
        // Starting in ASP.NET 7.0, the authentication stack integrates a fallback
        // mechanism to select the default scheme to use when no value is set, but
        // only if a single handler has been registered in the authentication options.
        //
        // Unfortunately, this behavior is problematic for OpenIddict as it enforces
        // strict checks to prevent calling certain unsafe authentication operations
        // on invalid endpoints. To opt out this undesirable behavior, a fake entry
        // is dynamically added if one of the default schemes properties is not set
        // and less than 2 handlers were registered in the authentication options.
        if (options.SchemeMap.Count < 2 && string.IsNullOrEmpty(options.DefaultScheme) &&
           (string.IsNullOrEmpty(options.DefaultSignInScheme) ||
            string.IsNullOrEmpty(options.DefaultSignOutScheme)))
        {
            options.AddScheme<IAuthenticationHandler>(Guid.NewGuid().ToString(), displayName: null);
        }
#endif

        static bool TryValidate(IDictionary<string, AuthenticationSchemeBuilder> map, string? scheme)
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
