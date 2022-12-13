/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.ComponentModel;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.Options;

namespace OpenIddict.Client.DataProtection;

/// <summary>
/// Contains the methods required to ensure that the OpenIddict ASP.NET Core Data Protection configuration is valid.
/// </summary>
[EditorBrowsable(EditorBrowsableState.Advanced)]
public sealed class OpenIddictClientDataProtectionConfiguration : IConfigureOptions<OpenIddictClientOptions>,
                                                                  IPostConfigureOptions<OpenIddictClientDataProtectionOptions>
{
    private readonly IDataProtectionProvider _dataProtectionProvider;

    /// <summary>
    /// Creates a new instance of the <see cref="OpenIddictClientDataProtectionConfiguration"/> class.
    /// </summary>
    /// <param name="dataProtectionProvider">The ASP.NET Core Data Protection provider.</param>
    public OpenIddictClientDataProtectionConfiguration(IDataProtectionProvider dataProtectionProvider)
        => _dataProtectionProvider = dataProtectionProvider;

    /// <inheritdoc/>
    public void Configure(OpenIddictClientOptions options)
    {
        if (options is null)
        {
            throw new ArgumentNullException(nameof(options));
        }

        // Register the built-in event handlers used by the OpenIddict Data Protection server components.
        options.Handlers.AddRange(OpenIddictClientDataProtectionHandlers.DefaultHandlers);
    }

    /// <inheritdoc/>
    public void PostConfigure(string? name, OpenIddictClientDataProtectionOptions options)
    {
        if (options is null)
        {
            throw new ArgumentNullException(nameof(options));
        }

        options.DataProtectionProvider ??= _dataProtectionProvider;
    }
}
