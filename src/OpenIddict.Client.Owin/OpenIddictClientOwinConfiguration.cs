/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.ComponentModel;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Owin;

namespace OpenIddict.Client.Owin;

/// <summary>
/// Contains the methods required to ensure that the OpenIddict client configuration is valid.
/// </summary>
[EditorBrowsable(EditorBrowsableState.Advanced)]
public sealed class OpenIddictClientOwinConfiguration : IConfigureOptions<OpenIddictClientOptions>,
                                                        IPostConfigureOptions<OpenIddictClientOwinOptions>
{
    private readonly IServiceProvider _provider;

    /// <summary>
    /// Creates a new instance of the <see cref="OpenIddictClientOwinConfiguration"/> class.
    /// </summary>
    /// <param name="provider">The service provider.</param>
    public OpenIddictClientOwinConfiguration(IServiceProvider provider)
        => _provider = provider ?? throw new ArgumentNullException(nameof(provider));

    /// <inheritdoc/>
    public void Configure(OpenIddictClientOptions options)
    {
        if (options is null)
        {
            throw new ArgumentNullException(nameof(options));
        }

        // Register the built-in event handlers used by the OpenIddict OWIN Client components.
        options.Handlers.AddRange(OpenIddictClientOwinHandlers.DefaultHandlers);
    }

    /// <inheritdoc/>
    public void PostConfigure(string? name, OpenIddictClientOwinOptions options)
    {
        if (options is null)
        {
            throw new ArgumentNullException(nameof(options));
        }

        // If no cookie manager was explicitly configured but the OWIN application builder was registered as a service
        // (which is required when using Autofac with the built-in Katana authentication middleware, as they require
        // injecting IAppBuilder in their constructor), try to resolve the default cookie manager provided by the
        // host. If it can't be resolved, use the generic implementation that directly operates on OWIN responses.
        options.CookieManager ??= _provider.GetService<IAppBuilder>() switch
        {
            // See https://github.com/aspnet/AspNetKatana/pull/486 for more information.
            IAppBuilder builder when builder.Properties.TryGetValue("infrastructure.CookieManager",
                out object? property) && property is ICookieManager manager => manager,

            _ => new CookieManager()
        };

        if (options.AuthenticationMode is AuthenticationMode.Active)
        {
            throw new InvalidOperationException(SR.GetResourceString(SR.ID0314));
        }

        if (!options.DisableAutomaticAuthenticationTypeForwarding)
        {
            foreach (var (provider, registrations) in _provider.GetRequiredService<IOptionsMonitor<OpenIddictClientOptions>>()
                .CurrentValue.Registrations
                .Where(registration => !string.IsNullOrEmpty(registration.ProviderName))
                .GroupBy(registration => registration.ProviderName)
                .Select(group => (ProviderName: group.Key, Registrations: group.ToList())))
            {
                // If an explicit mapping was already added, don't overwrite it.
                if (options.ForwardedAuthenticationTypes.Exists(type =>
                    string.Equals(type.AuthenticationType, provider, StringComparison.Ordinal)))
                {
                    continue;
                }

                // Ensure multiple client registrations don't share the same provider
                // name when automatic authentication type forwarding is enabled.
                if (registrations is not [OpenIddictClientRegistration registration])
                {
                    throw new InvalidOperationException(SR.FormatID0416(provider));
                }

                var description = new AuthenticationDescription
                {
                    AuthenticationType = registration.ProviderName
                };

                // Note: the AuthenticationDescription.Caption property setter doesn't no-op
                // when a null or empty display name is set. To ensure the "Caption" property
                // is not added to AuthenticationDescription.Properties when a null display
                // name is set, a null check is always performed first before assigning it.
                if (!string.IsNullOrEmpty(registration.ProviderDisplayName))
                {
                    description.Caption = registration.ProviderDisplayName;
                }

                options.ForwardedAuthenticationTypes.Add(description);
            }
        }
    }
}
