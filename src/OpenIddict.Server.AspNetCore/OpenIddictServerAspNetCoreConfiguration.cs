/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.ComponentModel;
using Microsoft.Extensions.Options;

namespace OpenIddict.Server.AspNetCore;

/// <summary>
/// Contains the methods required to ensure that the OpenIddict server configuration is valid.
/// </summary>
[EditorBrowsable(EditorBrowsableState.Advanced)]
public sealed class OpenIddictServerAspNetCoreConfiguration : IConfigureOptions<AuthenticationOptions>,
                                                              IConfigureOptions<OpenIddictServerOptions>,
                                                              IPostConfigureOptions<AuthenticationOptions>,
                                                              IPostConfigureOptions<OpenIddictServerOptions>,
                                                              IValidateOptions<AuthenticationOptions>,
                                                              IValidateOptions<OpenIddictServerAspNetCoreOptions>
{
    /// <inheritdoc/>
    public void Configure(AuthenticationOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);

        // Register the authentication scheme handler used by the OpenIddict ASP.NET Core server integration.
        if (!options.SchemeMap.ContainsKey(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme))
        {
            options.AddScheme<OpenIddictServerAspNetCoreHandler>(
                OpenIddictServerAspNetCoreDefaults.AuthenticationScheme, displayName: null);
        }
    }

    /// <inheritdoc/>
    public void Configure(OpenIddictServerOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);

        // Register the built-in event handlers used by the OpenIddict ASP.NET Core server components.
        options.Handlers.AddRange(OpenIddictServerAspNetCoreHandlers.DefaultHandlers);

        // Enable client_secret_basic support by default.
        options.ClientAuthenticationMethods.Add(ClientAuthenticationMethods.ClientSecretBasic);
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
           (string.IsNullOrEmpty(options.DefaultAuthenticateScheme) ||
            string.IsNullOrEmpty(options.DefaultChallengeScheme) ||
            string.IsNullOrEmpty(options.DefaultForbidScheme) ||
            string.IsNullOrEmpty(options.DefaultSignInScheme) ||
            string.IsNullOrEmpty(options.DefaultSignOutScheme)))
        {
            options.AddScheme<IAuthenticationHandler>(Guid.NewGuid().ToString(), displayName: null);
        }
    }

    /// <inheritdoc/>
    public void PostConfigure(string? name, OpenIddictServerOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);

        // Enable tls_client_auth and self_signed_tls_client_auth support if the
        // corresponding chain policies have been configured in the server options.
        if (options.PublicKeyInfrastructureTlsClientAuthenticationPolicy is not null)
        {
            options.ClientAuthenticationMethods.Add(ClientAuthenticationMethods.TlsClientAuth);
        }

        if (options.SelfSignedTlsClientAuthenticationPolicy is not null)
        {
            options.ClientAuthenticationMethods.Add(ClientAuthenticationMethods.SelfSignedTlsClientAuth);
        }
    }

    /// <inheritdoc/>
    public ValidateOptionsResult Validate(string? name, AuthenticationOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);

        var builder = new ValidateOptionsResultBuilder();

        if (!ValidateDefaultScheme(options.SchemeMap, options.DefaultAuthenticateScheme) ||
            !ValidateDefaultScheme(options.SchemeMap, options.DefaultChallengeScheme) ||
            !ValidateDefaultScheme(options.SchemeMap, options.DefaultForbidScheme) ||
            !ValidateDefaultScheme(options.SchemeMap, options.DefaultScheme) ||
            !ValidateDefaultScheme(options.SchemeMap, options.DefaultSignInScheme) ||
            !ValidateDefaultScheme(options.SchemeMap, options.DefaultSignOutScheme))
        {
            builder.AddError(SR.GetResourceString(SR.ID0109));
        }

        return builder.Build();

        static bool ValidateDefaultScheme(IDictionary<string, AuthenticationSchemeBuilder> map, string? scheme)
        {
            // If the scheme was not set or if it cannot be found in the map, return true.
            if (string.IsNullOrEmpty(scheme) || !map.TryGetValue(scheme, out var builder))
            {
                return true;
            }

            return builder.HandlerType != typeof(OpenIddictServerAspNetCoreHandler);
        }
    }

    /// <inheritdoc/>
    public ValidateOptionsResult Validate(string? name, OpenIddictServerAspNetCoreOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);

        var builder = new ValidateOptionsResultBuilder();

        if (options.EnableErrorPassthrough && options.EnableStatusCodePagesIntegration)
        {
            builder.AddError(SR.GetResourceString(SR.ID0110));
        }

        return builder.Build();
    }
}
