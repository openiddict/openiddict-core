/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.ComponentModel;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace OpenIddict.Client.AspNetCore.Bff;

/// <summary>
/// Contains the methods required to ensure that the OpenIddict BFF configuration is valid.
/// </summary>
[EditorBrowsable(EditorBrowsableState.Advanced)]
public sealed class OpenIddictClientAspNetCoreBffConfiguration : IPostConfigureOptions<OpenIddictClientOptions>,
                                                                 IPostConfigureOptions<OpenIddictClientAspNetCoreOptions>,
                                                                 IPostConfigureOptions<CookieAuthenticationOptions>,
                                                                 IValidateOptions<OpenIddictClientAspNetCoreBffOptions>
{
    private readonly IServiceProvider _provider;

    /// <summary>
    /// Creates a new instance of the <see cref="OpenIddictClientAspNetCoreBffConfiguration"/> class.
    /// </summary>
    /// <param name="provider">The service provider.</param>
    public OpenIddictClientAspNetCoreBffConfiguration(IServiceProvider provider)
        => _provider = provider ?? throw new ArgumentNullException(nameof(provider));

    /// <inheritdoc/>
    public void PostConfigure(string? name, OpenIddictClientOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);

        var settings = _provider.GetRequiredService<IOptionsMonitor<OpenIddictClientAspNetCoreBffOptions>>().CurrentValue;
        if (settings.DisableAutomaticEndpointRegistration)
        {
            return;
        }

        // Note: post-configuration is used to ensure the BFF endpoints are not removed
        // when the endpoint URIs are explicitly set using SetRedirectionEndpointUris().
        AddUri(options.RedirectionEndpointUris, settings.RedirectionPath);
        AddUri(options.PostLogoutRedirectionEndpointUris, settings.PostLogoutRedirectionPath);

        static void AddUri(List<Uri> uris, PathString path)
        {
            if (!path.HasValue)
            {
                return;
            }

            // Note: relative URIs are resolved against the base URI of the current request.
            var uri = new Uri(path.Value[1..], UriKind.Relative);
            if (!uris.Contains(uri))
            {
                uris.Add(uri);
            }
        }
    }

    /// <inheritdoc/>
    public void PostConfigure(string? name, OpenIddictClientAspNetCoreOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);

        var settings = _provider.GetRequiredService<IOptionsMonitor<OpenIddictClientAspNetCoreBffOptions>>().CurrentValue;
        if (settings.DisableAutomaticEndpointRegistration)
        {
            return;
        }

        // The BFF callback endpoints are handled by the endpoints mapped by MapOpenIddictBffEndpoints().
        options.EnableRedirectionEndpointPassthrough = true;
        options.EnablePostLogoutRedirectionEndpointPassthrough = true;
    }

    /// <inheritdoc/>
    public void PostConfigure(string? name, CookieAuthenticationOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);

        var settings = _provider.GetRequiredService<IOptionsMonitor<OpenIddictClientAspNetCoreBffOptions>>().CurrentValue;

        // If an explicit cookie scheme was configured, only attach the BFF logic to that scheme.
        if (!string.IsNullOrEmpty(settings.CookieScheme) && !string.Equals(name, settings.CookieScheme, StringComparison.Ordinal))
        {
            return;
        }

        var events = options.Events ??= new CookieAuthenticationEvents();

        var validate = events.OnValidatePrincipal;
        events.OnValidatePrincipal = async context =>
        {
            await validate(context);

            if (context.Principal is not null)
            {
                var manager = context.HttpContext.RequestServices.GetService<OpenIddictClientAspNetCoreBffTokenManager>() ??
                    throw new InvalidOperationException(SR.GetResourceString(SR.ID0561));

                await manager.ValidatePrincipalAsync(context);
            }
        };

        // Return 401/403 responses instead of redirecting API calls to the login/access denied pages.
        var login = events.OnRedirectToLogin;
        events.OnRedirectToLogin = context =>
        {
            if (OpenIddictClientAspNetCoreBffHelpers.IsBffApiRequest(context.HttpContext))
            {
                context.Response.StatusCode = StatusCodes.Status401Unauthorized;

                return Task.CompletedTask;
            }

            return login(context);
        };

        var denied = events.OnRedirectToAccessDenied;
        events.OnRedirectToAccessDenied = context =>
        {
            if (OpenIddictClientAspNetCoreBffHelpers.IsBffApiRequest(context.HttpContext))
            {
                context.Response.StatusCode = StatusCodes.Status403Forbidden;

                return Task.CompletedTask;
            }

            return denied(context);
        };
    }

    /// <inheritdoc/>
    public ValidateOptionsResult Validate(string? name, OpenIddictClientAspNetCoreBffOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);

        var builder = new ValidateOptionsResultBuilder();

        foreach (var (property, path) in new[]
        {
            (nameof(options.LoginPath), options.LoginPath),
            (nameof(options.LogoutPath), options.LogoutPath),
            (nameof(options.UserPath), options.UserPath),
            (nameof(options.BackchannelLogoutPath), options.BackchannelLogoutPath),
            (nameof(options.RedirectionPath), options.RedirectionPath),
            (nameof(options.PostLogoutRedirectionPath), options.PostLogoutRedirectionPath)
        })
        {
            if (!path.HasValue || path.Value.Length is < 2)
            {
                builder.AddError(SR.FormatID0559(property));
            }
        }

        if (options.AccessTokenRefreshMargin < TimeSpan.Zero || options.TokenRefreshResultRetentionPeriod < TimeSpan.Zero ||
            options.LogoutTokenReplayCacheLifetime < TimeSpan.Zero)
        {
            builder.AddError(SR.GetResourceString(SR.ID0560));
        }

        if (string.IsNullOrEmpty(options.AntiforgeryHeaderName) || string.IsNullOrEmpty(options.AntiforgeryHeaderValue))
        {
            builder.AddError(SR.GetResourceString(SR.ID0563));
        }

        return builder.Build();
    }
}
