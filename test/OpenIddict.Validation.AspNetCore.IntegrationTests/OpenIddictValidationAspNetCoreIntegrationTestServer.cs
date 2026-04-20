/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Hosting;
using OpenIddict.Validation.IntegrationTests;

namespace OpenIddict.Validation.AspNetCore.IntegrationTests;

/// <summary>
/// Represents a test host used by the validation integration tests.
/// </summary>
public class OpenIddictValidationAspNetCoreIntegrationTestServer : OpenIddictValidationIntegrationTestServer
{
    public OpenIddictValidationAspNetCoreIntegrationTestServer(IHost host)
    {
        Host = host;
        Server = host.GetTestServer();
    }

    /// <summary>
    /// Gets the generic host used by this instance.
    /// </summary>
    public IHost Host { get; }

    /// <summary>
    /// Gets the ASP.NET Core test server used by this instance.
    /// </summary>
    public TestServer Server { get; }

    public override ValueTask<OpenIddictValidationIntegrationTestClient> CreateClientAsync()
        => new(new OpenIddictValidationIntegrationTestClient(Server.CreateClient()));

    public override async ValueTask DisposeAsync()
    {
        // Dispose of the underlying test server.
        Server.Dispose();

        // Stop and dispose of the underlying generic host.
        await Host.StopAsync();
        Host.Dispose();
    }
}
