/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.ComponentModel;
using System.Diagnostics.CodeAnalysis;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;
using OpenIddict.Client.AspNetCore.Bff;

namespace Microsoft.Extensions.DependencyInjection;

/// <summary>
/// Exposes the necessary methods required to configure the OpenIddict backend-for-frontend (BFF) components.
/// </summary>
public sealed class OpenIddictClientAspNetCoreBffBuilder
{
    /// <summary>
    /// Initializes a new instance of <see cref="OpenIddictClientAspNetCoreBffBuilder"/>.
    /// </summary>
    /// <param name="services">The services collection.</param>
    public OpenIddictClientAspNetCoreBffBuilder(IServiceCollection services)
        => Services = services ?? throw new ArgumentNullException(nameof(services));

    /// <summary>
    /// Gets the services collection.
    /// </summary>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public IServiceCollection Services { get; }

    /// <summary>
    /// Enables validation of options during application startup.
    /// </summary>
    /// <returns>The <see cref="OpenIddictClientAspNetCoreBffBuilder"/> instance.</returns>
    public OpenIddictClientAspNetCoreBffBuilder ValidateOnStart()
    {
        Services.AddOptionsWithValidateOnStart<OpenIddictClientAspNetCoreBffOptions>();

        return this;
    }

    /// <summary>
    /// Amends the default OpenIddict BFF configuration.
    /// </summary>
    /// <param name="configuration">The delegate used to configure the OpenIddict options.</param>
    /// <remarks>This extension can be safely called multiple times.</remarks>
    /// <returns>The <see cref="OpenIddictClientAspNetCoreBffBuilder"/> instance.</returns>
    [EditorBrowsable(EditorBrowsableState.Advanced)]
    public OpenIddictClientAspNetCoreBffBuilder Configure(Action<OpenIddictClientAspNetCoreBffOptions> configuration)
    {
        ArgumentNullException.ThrowIfNull(configuration);

        Services.Configure(configuration);

        return this;
    }

    /// <summary>
    /// Sets the cookie authentication scheme storing the user session and tokens.
    /// </summary>
    /// <param name="scheme">The authentication scheme.</param>
    /// <returns>The <see cref="OpenIddictClientAspNetCoreBffBuilder"/> instance.</returns>
    public OpenIddictClientAspNetCoreBffBuilder SetCookieScheme(string scheme)
    {
        ArgumentException.ThrowIfNullOrEmpty(scheme);

        return Configure(options => options.CookieScheme = scheme);
    }

    /// <summary>
    /// Disables the automatic refresh of the access tokens stored in the authentication cookie.
    /// </summary>
    /// <returns>The <see cref="OpenIddictClientAspNetCoreBffBuilder"/> instance.</returns>
    public OpenIddictClientAspNetCoreBffBuilder DisableAutomaticTokenRefresh()
        => Configure(options => options.DisableAutomaticTokenRefresh = true);

    /// <summary>
    /// Sets the margin applied to the expiration date of access tokens when determining whether they must be refreshed.
    /// </summary>
    /// <param name="margin">The margin.</param>
    /// <returns>The <see cref="OpenIddictClientAspNetCoreBffBuilder"/> instance.</returns>
    public OpenIddictClientAspNetCoreBffBuilder SetAccessTokenRefreshMargin(TimeSpan margin)
        => Configure(options => options.AccessTokenRefreshMargin = margin);

    /// <summary>
    /// Sets the period during which refresh token results are returned to requests carrying the same refresh token.
    /// </summary>
    /// <param name="period">The retention period (<see cref="TimeSpan.Zero"/> to disable retention).</param>
    /// <returns>The <see cref="OpenIddictClientAspNetCoreBffBuilder"/> instance.</returns>
    public OpenIddictClientAspNetCoreBffBuilder SetTokenRefreshResultRetentionPeriod(TimeSpan period)
        => Configure(options => options.TokenRefreshResultRetentionPeriod = period);

    /// <summary>
    /// Enables the use of the <see cref="Microsoft.Extensions.Caching.Distributed.IDistributedCache"/> registered in the
    /// dependency injection container to share the refresh token results between multiple instances of the application
    /// and requires a distributed cache to be registered. The in-memory cache is used when distributed caching is not enabled.
    /// Note: the identifiers of the logout tokens are always shared by the OpenIddict client stack when a distributed cache is registered.
    /// </summary>
    /// <param name="timeout">
    /// The maximum period during which an instance waits for the result of a refresh
    /// token request sent by another instance, or <see langword="null"/> to use the default value.
    /// </param>
    /// <returns>The <see cref="OpenIddictClientAspNetCoreBffBuilder"/> instance.</returns>
    public OpenIddictClientAspNetCoreBffBuilder EnableDistributedCaching(TimeSpan? timeout = null)
        => Configure(options =>
        {
            options.EnableDistributedCaching = true;

            if (timeout is TimeSpan value)
            {
                options.DistributedTokenRefreshLockTimeout = value;
            }
        });

    /// <summary>
    /// Sets the name and value of the antiforgery header required by the user and API endpoints.
    /// </summary>
    /// <param name="name">The header name.</param>
    /// <param name="value">The header value.</param>
    /// <returns>The <see cref="OpenIddictClientAspNetCoreBffBuilder"/> instance.</returns>
    public OpenIddictClientAspNetCoreBffBuilder SetAntiforgeryHeader(string name, string value)
    {
        ArgumentException.ThrowIfNullOrEmpty(name);
        ArgumentException.ThrowIfNullOrEmpty(value);

        return Configure(options =>
        {
            options.AntiforgeryHeaderName = name;
            options.AntiforgeryHeaderValue = value;
        });
    }

    /// <summary>
    /// Sets the paths of the BFF endpoints. Paths left <see langword="null"/> are not changed.
    /// </summary>
    /// <param name="login">The login endpoint path.</param>
    /// <param name="logout">The logout endpoint path.</param>
    /// <param name="user">The user endpoint path.</param>
    /// <param name="backchannelLogout">The back-channel logout endpoint path.</param>
    /// <param name="redirection">The redirection (login callback) endpoint path.</param>
    /// <param name="postLogoutRedirection">The post-logout redirection (logout callback) endpoint path.</param>
    /// <returns>The <see cref="OpenIddictClientAspNetCoreBffBuilder"/> instance.</returns>
    public OpenIddictClientAspNetCoreBffBuilder SetEndpointPaths(
        string? login = null, string? logout = null, string? user = null,
        string? backchannelLogout = null, string? redirection = null, string? postLogoutRedirection = null)
        => Configure(options =>
        {
            options.LoginPath = login is not null ? new PathString(login) : options.LoginPath;
            options.LogoutPath = logout is not null ? new PathString(logout) : options.LogoutPath;
            options.UserPath = user is not null ? new PathString(user) : options.UserPath;
            options.BackchannelLogoutPath = backchannelLogout is not null ? new PathString(backchannelLogout) : options.BackchannelLogoutPath;
            options.RedirectionPath = redirection is not null ? new PathString(redirection) : options.RedirectionPath;
            options.PostLogoutRedirectionPath = postLogoutRedirection is not null
                ? new PathString(postLogoutRedirection) : options.PostLogoutRedirectionPath;
        });

    /// <summary>
    /// Prevents the BFF callback paths from being added to the OpenIddict client options
    /// and the pass-through mode of the callback endpoints from being enabled.
    /// </summary>
    /// <returns>The <see cref="OpenIddictClientAspNetCoreBffBuilder"/> instance.</returns>
    public OpenIddictClientAspNetCoreBffBuilder DisableAutomaticEndpointRegistration()
        => Configure(options => options.DisableAutomaticEndpointRegistration = true);

    /// <summary>
    /// Sets the default local return URL.
    /// </summary>
    /// <param name="url">The local URL.</param>
    /// <returns>The <see cref="OpenIddictClientAspNetCoreBffBuilder"/> instance.</returns>
    public OpenIddictClientAspNetCoreBffBuilder SetDefaultReturnUrl(string url)
    {
        ArgumentException.ThrowIfNullOrEmpty(url);

        return Configure(options => options.DefaultReturnUrl = url);
    }

    /// <summary>
    /// Registers an in-memory server-side session store supporting back-channel logout
    /// and attaches it to the BFF cookie scheme (or to all cookie schemes if no scheme was set).
    /// </summary>
    /// <remarks>Sessions are lost when the application restarts and are not shared between instances.</remarks>
    /// <returns>The <see cref="OpenIddictClientAspNetCoreBffBuilder"/> instance.</returns>
    public OpenIddictClientAspNetCoreBffBuilder UseInMemorySessionStore()
    {
        Services.TryAddSingleton<OpenIddictClientAspNetCoreBffMemorySessionStore>();

        Services.TryAddEnumerable(ServiceDescriptor.Singleton<
            IPostConfigureOptions<CookieAuthenticationOptions>, OpenIddictClientAspNetCoreBffSessionStoreConfiguration>());

        return this;
    }

    /// <summary>
    /// Registers a handler invoked when a valid back-channel logout notification is received.
    /// </summary>
    /// <typeparam name="THandler">The handler type.</typeparam>
    /// <returns>The <see cref="OpenIddictClientAspNetCoreBffBuilder"/> instance.</returns>
    public OpenIddictClientAspNetCoreBffBuilder AddBackchannelLogoutHandler<
        [DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.PublicConstructors)] THandler>()
        where THandler : class, IOpenIddictClientAspNetCoreBffBackchannelLogoutHandler
    {
        Services.TryAddEnumerable(ServiceDescriptor.Scoped<IOpenIddictClientAspNetCoreBffBackchannelLogoutHandler, THandler>());

        return this;
    }
}
