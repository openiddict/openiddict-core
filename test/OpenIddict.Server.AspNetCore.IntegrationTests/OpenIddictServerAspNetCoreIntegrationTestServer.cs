/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Diagnostics.CodeAnalysis;
using Microsoft.AspNetCore.TestHost;
using OpenIddict.Server.IntegrationTests;

#if SUPPORTS_GENERIC_HOST
using Microsoft.Extensions.Hosting;
#endif

namespace OpenIddict.Server.AspNetCore.IntegrationTests;

/// <summary>
/// Represents a test host used by the server integration tests.
/// </summary>
public class OpenIddictServerAspNetCoreIntegrationTestServer : OpenIddictServerIntegrationTestServer
{
#if SUPPORTS_GENERIC_HOST
    public OpenIddictServerAspNetCoreIntegrationTestServer(IHost host)
    {
        Host = host;
        Server = host.GetTestServer();
    }

    /// <summary>
    /// Gets the generic host used by this instance.
    /// </summary>
    public IHost Host { get; }
#else
    public OpenIddictServerAspNetCoreIntegrationTestServer(TestServer server)
        => Server = server;
#endif

    /// <summary>
    /// Gets the ASP.NET Core test server used by this instance.
    /// </summary>
    public TestServer Server { get; }

    public override ValueTask<OpenIddictServerIntegrationTestClient> CreateClientAsync()
        => new(new OpenIddictServerIntegrationTestClient(Server.CreateClient()));

    public override
#if SUPPORTS_GENERIC_HOST
        async
#endif
        ValueTask DisposeAsync()
    {
        // Dispose of the underlying test server.
        Server.Dispose();

#if SUPPORTS_GENERIC_HOST
        // Stop and dispose of the underlying generic host.
        await Host.StopAsync();
        Host.Dispose();
#else
        return default;
#endif
    }
}
