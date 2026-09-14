/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.ComponentModel;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Primitives;

namespace OpenIddict.Client.AspNetCore;

/// <summary>
/// Contains the methods required to ensure that the OpenIddict client configuration is valid.
/// </summary>
[EditorBrowsable(EditorBrowsableState.Advanced)]
public sealed class OpenIddictClientAspNetCoreConfiguration : IConfigureOptions<AuthenticationOptions>,
                                                              IConfigureOptions<OpenIddictClientOptions>,
                                                              IPostConfigureOptions<AuthenticationOptions>,
                                                              IPostConfigureOptions<OpenIddictClientAspNetCoreOptions>,
                                                              IValidateOptions<AuthenticationOptions>,
                                                              IValidateOptions<OpenIddictClientAspNetCoreOptions>,
                                                              IOptionsChangeTokenSource<OpenIddictClientAspNetCoreOptions>
{
    private readonly IServiceProvider _provider;

    /// <summary>
    /// Creates a new instance of the <see cref="OpenIddictClientAspNetCoreConfiguration"/> class.
    /// </summary>
    /// <param name="provider">The service provider.</param>
    public OpenIddictClientAspNetCoreConfiguration(IServiceProvider provider)
        => _provider = provider ?? throw new ArgumentNullException(nameof(provider));

    /// <inheritdoc/>
    public void Configure(AuthenticationOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);

        // Register the authentication scheme handler used by the OpenIddict ASP.NET Core client integration.
        if (!options.SchemeMap.ContainsKey(OpenIddictClientAspNetCoreDefaults.AuthenticationScheme))
        {
            options.AddScheme<OpenIddictClientAspNetCoreHandler>(
                OpenIddictClientAspNetCoreDefaults.AuthenticationScheme, displayName: null);
        }

        // Resolve the forwarded authentication schemes managed by the OpenIddict ASP.NET Core
        // client host and add an entry for each scheme in the ASP.NET Core authentication options.
        foreach (var scheme in _provider.GetRequiredService<IOptionsMonitor<OpenIddictClientAspNetCoreOptions>>()
            .CurrentValue.ForwardedAuthenticationSchemes)
        {
            if (!options.SchemeMap.ContainsKey(scheme.Name))
            {
                options.AddScheme<OpenIddictClientAspNetCoreForwarder>(scheme.Name, scheme.DisplayName);
            }
        }
    }

    /// <inheritdoc/>
    public void PostConfigure(string? name, OpenIddictClientAspNetCoreOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);

        if (!options.DisableAutomaticAuthenticationSchemeForwarding)
        {
            foreach (var (provider, registrations) in _provider.GetRequiredService<IOptionsMonitor<OpenIddictClientOptions>>()
                .CurrentValue.Registrations
                .Where(static registration => !string.IsNullOrEmpty(registration.ProviderName))
                .GroupBy(static registration => registration.ProviderName, StringComparer.Ordinal)
                .Select(static group => (ProviderName: group.Key, Registrations: group.ToList())))
            {
                // If an explicit mapping was already added, don't overwrite it.
                if (options.ForwardedAuthenticationSchemes.Exists(scheme =>
                    string.Equals(scheme.Name, provider, StringComparison.Ordinal)))
                {
                    continue;
                }

                if (registrations is not [OpenIddictClientRegistration registration])
                {
                    continue;
                }

                options.ForwardedAuthenticationSchemes.Add(new AuthenticationScheme(
                    name       : registration.ProviderName!,
                    displayName: registration.ProviderDisplayName,
                    handlerType: typeof(OpenIddictClientAspNetCoreForwarder)));
            }
        }
    }

    /// <inheritdoc/>
    public void Configure(OpenIddictClientOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);

        // Register the built-in event handlers used by the OpenIddict ASP.NET Core client components.
        options.Handlers.AddRange(OpenIddictClientAspNetCoreHandlers.DefaultHandlers);
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
            string.IsNullOrEmpty(options.DefaultSignInScheme) ||
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

        // Ensure the default schemes are not mapped to the OpenIddict client handler or forwarder.
        if (!ValidateDefaultScheme(options.SchemeMap, options.DefaultAuthenticateScheme) ||
            !ValidateDefaultScheme(options.SchemeMap, options.DefaultScheme) ||
            !ValidateDefaultScheme(options.SchemeMap, options.DefaultSignInScheme) ||
            !ValidateDefaultScheme(options.SchemeMap, options.DefaultSignOutScheme))
        {
            builder.AddError(SR.GetResourceString(SR.ID0289));
        }

        // Ensure the main authentication scheme was not hijacked by another component
        // and that the handler type corresponds to the OpenIddict client handler.
        if (!ValidateHandlerType<OpenIddictClientAspNetCoreHandler>(
            options.SchemeMap, OpenIddictClientAspNetCoreDefaults.AuthenticationScheme))
        {
            builder.AddError(SR.GetResourceString(SR.ID0288));
        }

        // Ensure the forwarded authentication schemes are mapped to the OpenIddict client forwarder.
        foreach (var group in _provider.GetRequiredService<IOptionsMonitor<OpenIddictClientAspNetCoreOptions>>()
            .CurrentValue.ForwardedAuthenticationSchemes
            .GroupBy(static scheme => scheme.Name, StringComparer.Ordinal)
            .Where(group => !ValidateHandlerType<OpenIddictClientAspNetCoreForwarder>(options.SchemeMap, group.Key)))
        {
            builder.AddError(SR.FormatID0414(group.Key));
        }

        return builder.Build();

        static bool ValidateDefaultScheme(IDictionary<string, AuthenticationSchemeBuilder> map, string? scheme)
        {
            // If the scheme was not set or if it cannot be found in the map, return true.
            if (string.IsNullOrEmpty(scheme) || !map.TryGetValue(scheme, out var builder))
            {
                return true;
            }

            return builder.HandlerType != typeof(OpenIddictClientAspNetCoreHandler) &&
                   builder.HandlerType != typeof(OpenIddictClientAspNetCoreForwarder);
        }

        static bool ValidateHandlerType<THandler>(IDictionary<string, AuthenticationSchemeBuilder> map, string? scheme)
            where THandler : IAuthenticationHandler
        {
            // If the scheme was not set or if it cannot be found in the map, return true.
            if (string.IsNullOrEmpty(scheme) || !map.TryGetValue(scheme, out var builder))
            {
                return true;
            }

            return builder.HandlerType == typeof(THandler);
        }
    }

    /// <inheritdoc/>
    public ValidateOptionsResult Validate(string? name, OpenIddictClientAspNetCoreOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);

        var builder = new ValidateOptionsResultBuilder();

        // Ensure multiple client registrations don't share the same provider
        // name when automatic authentication scheme forwarding is enabled.
        if (!options.DisableAutomaticAuthenticationSchemeForwarding)
        {
            foreach (var (provider, registrations) in _provider.GetRequiredService<IOptionsMonitor<OpenIddictClientOptions>>()
                .CurrentValue.Registrations
                .Where(static registration => !string.IsNullOrEmpty(registration.ProviderName))
                .GroupBy(static registration => registration.ProviderName, StringComparer.Ordinal)
                .Select(static group => (ProviderName: group.Key, Registrations: group.ToList()))
                .Where(static group => group.Registrations.Count is > 1))
            {
                builder.AddError(SR.FormatID0415(provider));
            }
        }

        // Ensure the back-channel and front-channel logout endpoints, if enabled, can terminate sessions.
        var client = _provider.GetRequiredService<IOptionsMonitor<OpenIddictClientOptions>>().CurrentValue;

        // Note: if the service provider doesn't implement IServiceProviderIsService, the session stores are assumed to be registered.
        var stores = _provider.GetService<IServiceProviderIsService>()?.IsService(typeof(IOpenIddictClientSessionStore)) ?? true;

        // As required by OpenID Connect Back-Channel Logout 1.0, section 2.8, the relying party MUST return
        // an error if the logout failed: since no session can be terminated without a session store, the
        // pass-through mode or a custom event handler, reject this configuration when the options are resolved.
        if (client.BackchannelLogoutEndpointUris.Count is not 0 && !options.EnableBackchannelLogoutEndpointPassthrough &&
            !stores && !HasCustomHandler<HandleBackchannelLogoutRequestContext>(client))
        {
            builder.AddError(SR.GetResourceString(SR.ID0760));
        }

        // Note: session stores are only invoked for unverified front-channel logout requests when session verification
        // is disabled. Otherwise, the sign-out scheme is needed to verify the request and terminate the local session.
        if (client.FrontchannelLogoutEndpointUris.Count is not 0 && !options.EnableFrontchannelLogoutEndpointPassthrough &&
            string.IsNullOrEmpty(options.FrontchannelLogoutSignOutScheme) && !(stores && client.DisableFrontchannelLogoutSessionVerification) &&
            !HasCustomHandler<HandleFrontchannelLogoutRequestContext>(client))
        {
            builder.AddError(SR.GetResourceString(SR.ID0766));
        }

        return builder.Build();

        static bool HasCustomHandler<TContext>(OpenIddictClientOptions options) where TContext : BaseContext
            => options.Handlers.Exists(static descriptor => descriptor.ContextType == typeof(TContext) &&
                                                            descriptor.Type is OpenIddictClientHandlerType.Custom);
    }

    /// <inheritdoc/>
    IChangeToken IOptionsChangeTokenSource<OpenIddictClientAspNetCoreOptions>.GetChangeToken() => new CompositeChangeToken(
    [
        // Force the options to be re-evaluated when the related instances from which they are populated are changed.
        .. from source in _provider.GetServices<IOptionsChangeTokenSource<OpenIddictClientOptions>>()
           select source.GetChangeToken()
    ]);

    /// <inheritdoc/>
    string? IOptionsChangeTokenSource<OpenIddictClientAspNetCoreOptions>.Name => Options.DefaultName;
}
