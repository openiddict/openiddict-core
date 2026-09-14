/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.ComponentModel;
using System.Net.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Http;
using Microsoft.Extensions.Options;

namespace OpenIddict.Server.SystemNetHttp;

/// <summary>
/// Contains the methods required to ensure that the OpenIddict server/System.Net.Http integration configuration is valid.
/// </summary>
[EditorBrowsable(EditorBrowsableState.Advanced)]
public sealed class OpenIddictServerSystemNetHttpConfiguration : IConfigureOptions<OpenIddictServerOptions>,
                                                                 IConfigureNamedOptions<HttpClientFactoryOptions>
{
    /// <summary>
    /// Gets the name of the <see cref="HttpClient"/> used to send backchannel notifications and back-channel logout requests.
    /// </summary>
    public static string HttpClientName => OpenIddictServerSystemNetHttpConstants.HttpClientName;

    private readonly IServiceProvider _provider;

    /// <summary>
    /// Creates a new instance of the <see cref="OpenIddictServerSystemNetHttpConfiguration"/> class.
    /// </summary>
    /// <param name="provider">The service provider.</param>
    public OpenIddictServerSystemNetHttpConfiguration(IServiceProvider provider)
        => _provider = provider ?? throw new ArgumentNullException(nameof(provider));

    /// <inheritdoc/>
    public void Configure(OpenIddictServerOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);

        // Register the built-in event handlers used by the OpenIddict System.Net.Http server components.
        options.Handlers.AddRange(OpenIddictServerSystemNetHttpHandlers.DefaultHandlers);
    }

    /// <inheritdoc/>
    public void Configure(HttpClientFactoryOptions options) => Configure(Options.DefaultName, options);

    /// <inheritdoc/>
    public void Configure(string? name, HttpClientFactoryOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);

        // Only amend the HTTP client factory options if the instance is managed by OpenIddict.
        if (!string.Equals(name, HttpClientName, StringComparison.Ordinal))
        {
            return;
        }

        var settings = _provider.GetRequiredService<IOptionsMonitor<OpenIddictServerSystemNetHttpOptions>>().CurrentValue;

        options.HttpClientActions.Add(client =>
        {
            // Note: client notification endpoints are not expected to return a response body
            // (a 204 status code is recommended), so a very low buffer size limit is used.
            client.MaxResponseContentBufferSize = 64 * 1024;
            client.Timeout = settings.Timeout;
        });

        foreach (var action in settings.HttpClientActions)
        {
            options.HttpClientActions.Add(action);
        }

        options.HttpMessageHandlerBuilderActions.Add(static builder =>
        {
            // Note: the OP MUST NOT follow redirects returned by client notification or back-channel logout endpoints.
            //
            // See https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.10.2.
            //
            // Cookies are never used by client notification endpoints: they are disabled to prevent cookies
            // returned by an endpoint from being attached to notifications sent to other client applications.
            switch (builder.PrimaryHandler)
            {
                case HttpClientHandler handler:
                    handler.AllowAutoRedirect = false;
                    handler.UseCookies = false;
                    break;

                // Note: Microsoft.Extensions.Http 9.0+ uses SocketsHttpHandler as the default primary handler on
                // platforms that support it. Since the user-defined handler actions require an HttpClientHandler
                // instance, it is replaced here. Custom primary handlers (e.g test handlers) are left untouched.
#if NET
                case SocketsHttpHandler:
#endif
                case null:
                    builder.PrimaryHandler = new HttpClientHandler { AllowAutoRedirect = false, UseCookies = false };
                    break;
            }
        });

        foreach (var action in settings.HttpClientHandlerActions)
        {
            options.HttpMessageHandlerBuilderActions.Add(builder => action(builder.PrimaryHandler as HttpClientHandler
                ?? throw new InvalidOperationException(SR.FormatID0373(typeof(HttpClientHandler).FullName))));
        }
    }
}
