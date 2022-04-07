/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using Microsoft.Extensions.Options;

namespace OpenIddict.Server.AspNetCore;

/// <summary>
/// Contains the methods required to ensure that the OpenIddict server configuration is valid.
/// </summary>
public class OpenIddictServerAspNetCoreConfiguration : IConfigureOptions<AuthenticationOptions>,
                                                       IConfigureOptions<OpenIddictServerOptions>,
                                                       IPostConfigureOptions<AuthenticationOptions>,
                                                       IPostConfigureOptions<OpenIddictServerAspNetCoreOptions>
{
    /// <summary>
    /// Registers the OpenIddict server handler in the global authentication options.
    /// </summary>
    /// <param name="options">The options instance to initialize.</param>
    public void Configure(AuthenticationOptions options!!)
    {
        // If a handler was already registered and the type doesn't correspond to the OpenIddict handler, throw an exception.
        if (options.SchemeMap.TryGetValue(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme, out var builder) &&
            builder.HandlerType != typeof(OpenIddictServerAspNetCoreHandler))
        {
            throw new InvalidOperationException(SR.GetResourceString(SR.ID0108));
        }

        options.AddScheme<OpenIddictServerAspNetCoreHandler>(
            OpenIddictServerAspNetCoreDefaults.AuthenticationScheme, displayName: null);
    }

    public void Configure(OpenIddictServerOptions options!!)
    {
        // Register the built-in event handlers used by the OpenIddict ASP.NET Core server components.
        options.Handlers.AddRange(OpenIddictServerAspNetCoreHandlers.DefaultHandlers);
    }

    /// <summary>
    /// Ensures that the authentication configuration is in a consistent and valid state.
    /// </summary>
    /// <param name="name">The name of the options instance to configure, if applicable.</param>
    /// <param name="options">The options instance to initialize.</param>
    public void PostConfigure(string name, AuthenticationOptions options!!)
    {
        if (!TryValidate(options.SchemeMap, options.DefaultAuthenticateScheme) ||
            !TryValidate(options.SchemeMap, options.DefaultChallengeScheme) ||
            !TryValidate(options.SchemeMap, options.DefaultForbidScheme) ||
            !TryValidate(options.SchemeMap, options.DefaultScheme) ||
            !TryValidate(options.SchemeMap, options.DefaultSignInScheme) ||
            !TryValidate(options.SchemeMap, options.DefaultSignOutScheme))
        {
            throw new InvalidOperationException(SR.GetResourceString(SR.ID0109));
        }

        static bool TryValidate(IDictionary<string, AuthenticationSchemeBuilder> map, string? scheme)
        {
            // If the scheme was not set or if it cannot be found in the map, return true.
            if (string.IsNullOrEmpty(scheme) || !map.TryGetValue(scheme, out var builder))
            {
                return true;
            }

            return builder.HandlerType != typeof(OpenIddictServerAspNetCoreHandler);
        }
    }

    /// <summary>
    /// Populates the default OpenIddict server ASP.NET Core options and
    /// ensures that the configuration is in a consistent and valid state.
    /// </summary>
    /// <param name="name">The name of the options instance to configure, if applicable.</param>
    /// <param name="options">The options instance to initialize.</param>
    public void PostConfigure(string name, OpenIddictServerAspNetCoreOptions options!!)
    {
        if (options.EnableErrorPassthrough && options.EnableStatusCodePagesIntegration)
        {
            throw new InvalidOperationException(SR.GetResourceString(SR.ID0110));
        }
    }
}
