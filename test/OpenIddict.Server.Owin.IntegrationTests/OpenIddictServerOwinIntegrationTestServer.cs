/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Diagnostics.CodeAnalysis;
using Microsoft.Owin.Testing;
using OpenIddict.Server.IntegrationTests;

namespace OpenIddict.Server.Owin.IntegrationTests;

/// <summary>
/// Represents a test host used by the server integration tests.
/// </summary>
public class OpenIddictServerOwinIntegrationTestServer : OpenIddictServerIntegrationTestServer
{
    public OpenIddictServerOwinIntegrationTestServer(TestServer server)
        => Server = server;

    /// <summary>
    /// Gets the ASP.NET Core test server used by this instance.
    /// </summary>
    public TestServer Server { get; }

    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "The caller is responsible of disposing the test client.")]
    public override ValueTask<OpenIddictServerIntegrationTestClient> CreateClientAsync()
        => new(new OpenIddictServerIntegrationTestClient(Server.HttpClient));

    public override ValueTask DisposeAsync()
    {
        // Dispose of the underlying test server.
        Server.Dispose();

        return default;
    }
}
