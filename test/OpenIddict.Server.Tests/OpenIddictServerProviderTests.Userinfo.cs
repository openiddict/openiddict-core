/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Threading.Tasks;
using AspNet.Security.OpenIdConnect.Client;
using AspNet.Security.OpenIdConnect.Primitives;
using OpenIddict.Abstractions;
using Xunit;

namespace OpenIddict.Server.Tests
{
    public partial class OpenIddictServerProviderTests
    {
        [Fact]
        public async Task ExtractUserinfoRequest_RequestIsHandledByUserCode()
        {
            // Arrange
            var server = CreateAuthorizationServer();
            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync(UserinfoEndpoint, new OpenIdConnectRequest
            {
                AccessToken = "SlAV32hkKG"
            });

            // Assert
            Assert.Equal("SlAV32hkKG", (string) response[OpenIddictConstants.Parameters.AccessToken]);
            Assert.Equal("Bob le Bricoleur", (string) response[OpenIddictConstants.Claims.Subject]);
        }
    }
}
