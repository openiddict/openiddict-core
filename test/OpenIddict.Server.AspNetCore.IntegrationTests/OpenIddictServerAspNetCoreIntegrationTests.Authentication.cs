/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Threading.Tasks;
using Microsoft.Extensions.DependencyInjection;
using OpenIddict.Abstractions;
using OpenIddict.Server.FunctionalTests;
using Xunit;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace OpenIddict.Server.AspNetCore.FunctionalTests
{
    public partial class OpenIddictServerAspNetCoreIntegrationTests : OpenIddictServerIntegrationTests
    {
        [Fact(Skip = "The handler responsible of rejecting such requests has not been ported yet.")]
        public async Task ExtractAuthorizationRequest_RequestIdParameterIsRejectedWhenRequestCachingIsDisabled()
        {
            // Arrange
            await using var server = await CreateServerAsync(options => options.EnableDegradedMode());
            await using var client = await server.CreateClientAsync();

            // Act
            var response = await client.PostAsync("/connect/authorize", new OpenIddictRequest
            {
                RequestId = "EFAF3596-F868-497F-96BB-AA2AD1F8B7E7"
            });

            // Assert
            Assert.Equal(Errors.InvalidRequest, response.Error);
            Assert.Equal("The 'request_id' parameter is not supported.", response.ErrorDescription);
        }

        [Fact]
        public async Task ExtractAuthorizationRequest_InvalidRequestIdParameterIsRejected()
        {
            // Arrange
            await using var server = await CreateServerAsync(options =>
            {
                options.Services.AddDistributedMemoryCache();

                options.UseAspNetCore()
                       .EnableAuthorizationEndpointCaching();
            });

            await using var client = await server.CreateClientAsync();

            // Act
            var response = await client.PostAsync("/connect/authorize", new OpenIddictRequest
            {
                RequestId = "EFAF3596-F868-497F-96BB-AA2AD1F8B7E7"
            });

            // Assert
            Assert.Equal(Errors.InvalidRequest, response.Error);
            Assert.Equal("The specified 'request_id' parameter is invalid.", response.ErrorDescription);
        }
    }
}
