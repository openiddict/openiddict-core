/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Threading.Tasks;
using Microsoft.Owin.Testing;
using OpenIddict.Server.FunctionalTests;

namespace OpenIddict.Server.Owin.FunctionalTests
{
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

        public override ValueTask<OpenIddictServerIntegrationTestClient> CreateClientAsync()
            => new ValueTask<OpenIddictServerIntegrationTestClient>(
                new OpenIddictServerIntegrationTestClient(Server.HttpClient));

        public override ValueTask DisposeAsync()
        {
            // Dispose of the underlying test server.
            Server.Dispose();

            return default;
        }
    }
}