/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Diagnostics.CodeAnalysis;
using System.Threading.Tasks;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Hosting;
using OpenIddict.Server.IntegrationTests;

namespace OpenIddict.Server.AspNetCore.IntegrationTests
{
    /// <summary>
    /// Represents a test host used by the server integration tests.
    /// </summary>
    public class OpenIddictServerAspNetCoreIntegrationTestServer : OpenIddictServerIntegrationTestServer
    {
        public OpenIddictServerAspNetCoreIntegrationTestServer(TestServer server)
            => Server = server;

#if SUPPORTS_GENERIC_HOST
        public OpenIddictServerAspNetCoreIntegrationTestServer(IHost host)
        {
            Host = host;
            Server = host.GetTestServer();
        }
#endif

        /// <summary>
        /// Gets the ASP.NET Core test server used by this instance.
        /// </summary>
        public TestServer Server { get; }

#if SUPPORTS_GENERIC_HOST
        /// <summary>
        /// Gets the generic host used by this instance.
        /// </summary>
        public IHost Host { get; }
#endif

        [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
            Justification = "The caller is responsible of disposing the test client.")]
        public override ValueTask<OpenIddictServerIntegrationTestClient> CreateClientAsync()
            => new ValueTask<OpenIddictServerIntegrationTestClient>(
                new OpenIddictServerIntegrationTestClient(Server.CreateClient()));

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
}