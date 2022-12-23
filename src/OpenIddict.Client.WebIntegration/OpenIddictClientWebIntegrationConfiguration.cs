/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.ComponentModel;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Http;
using Microsoft.Extensions.Options;
using OpenIddict.Client.SystemNetHttp;
using static OpenIddict.Client.WebIntegration.OpenIddictClientWebIntegrationConstants;

namespace OpenIddict.Client.WebIntegration;

/// <summary>
/// Contains the methods required to ensure that the OpenIddict client Web integration configuration is valid.
/// </summary>
[EditorBrowsable(EditorBrowsableState.Advanced)]
public sealed partial class OpenIddictClientWebIntegrationConfiguration : IConfigureOptions<OpenIddictClientOptions>,
                                                                          IConfigureNamedOptions<HttpClientFactoryOptions>
{
#if !SUPPORTS_SERVICE_PROVIDER_IN_HTTP_MESSAGE_HANDLER_BUILDER
    private readonly IServiceProvider _provider;

    /// <summary>
    /// Creates a new instance of the <see cref="OpenIddictClientWebIntegrationConfiguration"/> class.
    /// </summary>
    /// <param name="provider">The service provider.</param>
    public OpenIddictClientWebIntegrationConfiguration(IServiceProvider provider)
        => _provider = provider ?? throw new ArgumentNullException(nameof(provider));
#endif

    /// <inheritdoc/>
    public void Configure(OpenIddictClientOptions options)
    {
        if (options is null)
        {
            throw new ArgumentNullException(nameof(options));
        }

        // Register the built-in event handlers used by the OpenIddict client Web components.
        options.Handlers.AddRange(OpenIddictClientWebIntegrationHandlers.DefaultHandlers);
    }

    /// <inheritdoc/>
    public void Configure(HttpClientFactoryOptions options) => Configure(Options.DefaultName, options);

    /// <inheritdoc/>
    public void Configure(string? name, HttpClientFactoryOptions options)
    {
        if (options is null)
        {
            throw new ArgumentNullException(nameof(options));
        }

        // Only amend the HTTP client factory options if the instance is managed by OpenIddict
        // and contains the name of a provider managed by OpenIddict.Client.WebIntegration.
        var assembly = typeof(OpenIddictClientSystemNetHttpOptions).Assembly.GetName();
        if (string.IsNullOrEmpty(name) || !name.StartsWith(assembly.Name!, StringComparison.Ordinal) ||
            name.Length < assembly.Name!.Length + 1 || name[assembly.Name.Length] is not ':')
        {
            return;
        }

        // Note: while not enforced yet, Pro Santé Connect's specification requires sending a TLS
        // client certificate when communicating with its backchannel OpenID Connect endpoints.
        //
        // For that, the primary HTTP handler must be altered or replaced by an instance that
        // includes the client certificate set in the options in its certificate collection.
        //
        // For more information, see EXI PSC 24 in the annex part of
        // https://www.legifrance.gouv.fr/jorf/id/JORFTEXT000045551195.
        if (name.AsSpan(assembly.Name.Length + 1) is Providers.ProSantéConnect)
        {
            options.HttpMessageHandlerBuilderActions.Add(builder =>
            {
                // Note: the client registration instance is not available here,
                // so the provider options must be resolved via the DI container.
#if SUPPORTS_SERVICE_PROVIDER_IN_HTTP_MESSAGE_HANDLER_BUILDER
                var options = builder.Services.GetRequiredService<IOptionsMonitor<
                    OpenIddictClientWebIntegrationOptions.ProSantéConnect>>().CurrentValue;
#else
                var options = _provider.GetRequiredService<IOptionsMonitor<
                    OpenIddictClientWebIntegrationOptions.ProSantéConnect>>().CurrentValue;
#endif
                if (builder.PrimaryHandler is not HttpClientHandler handler)
                {
                    throw new InvalidOperationException(SR.GetResourceString(SR.ID0373));
                }

                // If a client certificate was specified, update the HTTP handler to use it.
                if (options.ClientCertificate is X509Certificate certificate)
                {
                    handler.ClientCertificates.Add(certificate);
                    handler.ClientCertificateOptions = ClientCertificateOption.Manual;
                }
            });
        }
    }
}
