/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

namespace OpenIddict.Validation.IntegrationTests;

/// <summary>
/// Represents a test host used by the validation integration tests.
/// </summary>
public abstract class OpenIddictValidationIntegrationTestServer : IAsyncDisposable
{
    public abstract ValueTask<OpenIddictValidationIntegrationTestClient> CreateClientAsync();

    public virtual ValueTask DisposeAsync() => default;
}
