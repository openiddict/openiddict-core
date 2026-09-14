/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using static OpenIddict.Server.Saml.OpenIddictServerSamlModels;

namespace OpenIddict.Server.Saml;

/// <summary>
/// Provides methods allowing to store the SAML messages represented by the artifacts issued
/// using the HTTP-Artifact binding until they are resolved by the service providers.
/// </summary>
/// <remarks>
/// Implementations are resolved from the request services and can be registered with any lifetime.
/// In load-balanced deployments, implementations must be shared by all the instances and
/// <see cref="RemoveAsync(string, CancellationToken)"/> should be atomic to guarantee single use.
/// </remarks>
public interface IOpenIddictServerSamlArtifactStore
{
    /// <summary>
    /// Stores the message represented by an artifact.
    /// </summary>
    /// <param name="handle">The message handle of the artifact (an opaque, unguessable value).</param>
    /// <param name="message">The message.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.</returns>
    ValueTask AddAsync(string handle, ArtifactMessage message, CancellationToken cancellationToken);

    /// <summary>
    /// Retrieves and removes the message represented by an artifact, so that it can only be resolved once.
    /// </summary>
    /// <param name="handle">The message handle of the artifact.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>The message, or <see langword="null"/> if it cannot be found or was already resolved.</returns>
    ValueTask<ArtifactMessage?> RemoveAsync(string handle, CancellationToken cancellationToken);
}
