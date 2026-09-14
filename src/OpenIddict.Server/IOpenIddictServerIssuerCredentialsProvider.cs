/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

namespace OpenIddict.Server;

/// <summary>
/// Provides the signing and encryption credentials specific to an issuer when issuer resolution is enabled.
/// </summary>
public interface IOpenIddictServerIssuerCredentialsProvider
{
    /// <summary>
    /// Resolves the credentials that must be used to protect, unprotect and publish the keys of the specified issuer.
    /// </summary>
    /// <param name="issuer">The issuer resolved for the current request.</param>
    /// <param name="provider">The service provider used to resolve services.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask{TResult}"/> that can be used to monitor the asynchronous operation, whose result returns
    /// the credentials of the issuer (the preferred credentials first) or <see langword="null"/> to use the default
    /// credentials of the server (static credentials or automatically managed keys).
    /// </returns>
    ValueTask<OpenIddictServerCredentials?> GetCredentialsAsync(
        Uri issuer, IServiceProvider provider, CancellationToken cancellationToken);
}
