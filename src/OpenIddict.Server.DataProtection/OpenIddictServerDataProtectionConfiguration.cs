/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.ComponentModel;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.Options;

namespace OpenIddict.Server.DataProtection;

/// <summary>
/// Contains the methods required to ensure that the OpenIddict ASP.NET Core Data Protection configuration is valid.
/// </summary>
[EditorBrowsable(EditorBrowsableState.Advanced)]
public sealed class OpenIddictServerDataProtectionConfiguration : IConfigureOptions<OpenIddictServerOptions>,
                                                                  IPostConfigureOptions<OpenIddictServerDataProtectionOptions>
{
    private readonly IServiceProvider _provider;

    /// <summary>
    /// Creates a new instance of the <see cref="OpenIddictServerDataProtectionConfiguration"/> class.
    /// </summary>
    /// <param name="provider">The service provider used to resolve dependencies.</param>
    public OpenIddictServerDataProtectionConfiguration(IServiceProvider provider)
        => _provider = provider ?? throw new ArgumentNullException(nameof(provider));

    /// <inheritdoc/>
    public void Configure(OpenIddictServerOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);

        // Register the built-in event handlers used by the OpenIddict Data Protection server components.
        options.Handlers.AddRange(OpenIddictServerDataProtectionHandlers.DefaultHandlers);
    }

    /// <inheritdoc/>
    public void PostConfigure(string? name, OpenIddictServerDataProtectionOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);

        options.DataProtectionProvider ??= _provider.GetDataProtectionProvider();
    }
}
