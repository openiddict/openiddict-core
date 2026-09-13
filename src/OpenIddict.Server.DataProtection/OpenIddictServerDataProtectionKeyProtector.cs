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
/// Protects the automatically managed server keys using ASP.NET Core Data Protection.
/// </summary>
[EditorBrowsable(EditorBrowsableState.Advanced)]
public sealed class OpenIddictServerDataProtectionKeyProtector : IOpenIddictServerKeyProtector
{
    private readonly IOptionsMonitor<OpenIddictServerDataProtectionOptions> _options;

    /// <summary>
    /// Creates a new instance of the <see cref="OpenIddictServerDataProtectionKeyProtector"/> class.
    /// </summary>
    /// <param name="options">The OpenIddict ASP.NET Core Data Protection server options.</param>
    public OpenIddictServerDataProtectionKeyProtector(IOptionsMonitor<OpenIddictServerDataProtectionOptions> options)
        => _options = options ?? throw new ArgumentNullException(nameof(options));

    /// <inheritdoc/>
    public string Protect(string payload)
    {
        ArgumentException.ThrowIfNullOrEmpty(payload);

        return CreateProtector().Protect(payload);
    }

    /// <inheritdoc/>
    public string Unprotect(string payload)
    {
        ArgumentException.ThrowIfNullOrEmpty(payload);

        return CreateProtector().Unprotect(payload);
    }

    private IDataProtector CreateProtector() => _options.CurrentValue.DataProtectionProvider.CreateProtector(
        OpenIddictServerDataProtectionConstants.Purposes.Handlers.Server, "AutomaticKeyManagement");
}
