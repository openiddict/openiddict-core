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
    private readonly IDataProtectionProvider _dataProtectionProvider;

    /// <summary>
    /// Creates a new instance of the <see cref="OpenIddictServerDataProtectionConfiguration"/> class.
    /// </summary>
    /// <param name="dataProtectionProvider">The ASP.NET Core Data Protection provider.</param>
    public OpenIddictServerDataProtectionConfiguration(IDataProtectionProvider dataProtectionProvider)
        => _dataProtectionProvider = dataProtectionProvider;

    /// <inheritdoc/>
    public void Configure(OpenIddictServerOptions options)
    {
        if (options is null)
        {
            throw new ArgumentNullException(nameof(options));
        }

        // Register the built-in event handlers used by the OpenIddict Data Protection server components.
        options.Handlers.AddRange(OpenIddictServerDataProtectionHandlers.DefaultHandlers);
    }

    /// <inheritdoc/>
    public void PostConfigure(string? name, OpenIddictServerDataProtectionOptions options)
    {
        if (options is null)
        {
            throw new ArgumentNullException(nameof(options));
        }

        options.DataProtectionProvider ??= _dataProtectionProvider;
    }
}
