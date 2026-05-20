/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Security.Cryptography;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace OpenIddict.Core;

/// <summary>
/// Contains the methods required to ensure that the OpenIddict core configuration is valid.
/// </summary>
public class OpenIddictCoreConfiguration : IPostConfigureOptions<OpenIddictCoreOptions>, IValidateOptions<OpenIddictCoreOptions>
{
    private readonly IServiceProvider _provider;

    /// <summary>
    /// Creates a new instance of the <see cref="OpenIddictCoreConfiguration"/> class.
    /// </summary>
    /// <param name="provider">The service provider.</param>
    public OpenIddictCoreConfiguration(IServiceProvider provider)
        => _provider = provider ?? throw new ArgumentNullException(nameof(provider));

    /// <inheritdoc/>
    public void PostConfigure(string? name, OpenIddictCoreOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);

        options.TimeProvider ??= _provider.GetService<TimeProvider>() ?? TimeProvider.System;
    }

    /// <inheritdoc/>
    public ValidateOptionsResult Validate(string? name, OpenIddictCoreOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);

        var builder = new ValidateOptionsResultBuilder();

        // Ensure the options used to feed the PBKDF-based client secret protector respect
        // the minimum security requirements used in previous versions of OpenIddict.
        //
        // Note: the values used here MUST be kept in sync with the values in the application manager.
        if (options.ClientSecretKeyDerivationHashAlgorithm != HashAlgorithmName.SHA1   &&
            options.ClientSecretKeyDerivationHashAlgorithm != HashAlgorithmName.SHA256 &&
            options.ClientSecretKeyDerivationHashAlgorithm != HashAlgorithmName.SHA512)
        {
            builder.AddError(SR.FormatID0217(options.ClientSecretKeyDerivationHashAlgorithm.Name));
        }

        if (options.ClientSecretKeyDerivationIterations is not (>= 10_000 and <= 10_000_000))
        {
            builder.AddError(SR.FormatID0518(10_000, 10_000_000));
        }

        if (options.ClientSecretKeyDerivationSaltLength is not (>= 128 and <= 1024))
        {
            builder.AddError(SR.FormatID0519(128, 1024));
        }

        if (options.ClientSecretKeyDerivationOutputLength is not (>= 256 and <= 2048))
        {
            builder.AddError(SR.FormatID0520(256, 2048));
        }

        return builder.Build();
    }
}
