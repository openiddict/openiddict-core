/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Diagnostics.CodeAnalysis;
using Microsoft.Owin.Testing;
using OpenIddict.Validation.IntegrationTests;

namespace OpenIddict.Validation.Owin.IntegrationTests;

/// <summary>
/// Represents a test host used by the validation integration tests.
/// </summary>
public class OpenIddictValidationOwinIntegrationTestValidation : OpenIddictValidationIntegrationTestServer
{
    public OpenIddictValidationOwinIntegrationTestValidation(TestServer server)
        => Server = server;

    /// <summary>
    /// Gets the ASP.NET Core test server used by this instance.
    /// </summary>
    public TestServer Server { get; }

    public override ValueTask<OpenIddictValidationIntegrationTestClient> CreateClientAsync()
        => new(new OpenIddictValidationIntegrationTestClient(Server.HttpClient));

    public override ValueTask DisposeAsync()
    {
        // Dispose of the underlying test server.
        Server.Dispose();

        return default;
    }
}
