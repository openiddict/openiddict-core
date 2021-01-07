/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.DependencyInjection;
using Moq;
using OpenIddict.Abstractions;
using OpenIddict.Server.IntegrationTests;
using Xunit;
using static OpenIddict.Abstractions.OpenIddictConstants;
using static OpenIddict.Server.AspNetCore.OpenIddictServerAspNetCoreConstants;
using SR = OpenIddict.Abstractions.OpenIddictResources;

namespace OpenIddict.Server.AspNetCore.IntegrationTests
{
    public partial class OpenIddictServerAspNetCoreIntegrationTests : OpenIddictServerIntegrationTests
    {
        private const string LogoutEndpoint = "/connect/logout";

        [Fact(Skip = "The handler responsible of rejecting such requests has not been ported yet.")]
        public async Task ExtractLogoutRequest_RequestIdParameterIsRejectedWhenRequestCachingIsDisabled()
        {
            // Arrange
            await using var server = await CreateServerAsync(options => options.EnableDegradedMode());
            await using var client = await server.CreateClientAsync();

            // Act
            var response = await client.PostAsync(LogoutEndpoint, new OpenIddictRequest
            {
                RequestId = "EFAF3596-F868-497F-96BB-AA2AD1F8B7E7"
            });

            // Assert
            Assert.Equal(Errors.InvalidRequest, response.Error);
            Assert.Equal(SR.FormatID2028(Parameters.RequestId), response.ErrorDescription);
        }

        [Fact]
        public async Task ExtractLogoutRequest_InvalidRequestIdParameterIsRejected()
        {
            // Arrange
            await using var server = await CreateServerAsync(options =>
            {
                options.Services.AddDistributedMemoryCache();

                options.UseAspNetCore()
                       .EnableLogoutRequestCaching();
            });

            await using var client = await server.CreateClientAsync();

            // Act
            var response = await client.PostAsync(LogoutEndpoint, new OpenIddictRequest
            {
                RequestId = "EFAF3596-F868-497F-96BB-AA2AD1F8B7E7"
            });

            // Assert
            Assert.Equal(Errors.InvalidRequest, response.Error);
            Assert.Equal(SR.FormatID2052(Parameters.RequestId), response.ErrorDescription);
        }

        [Fact]
        public async Task CacheLogoutRequest_RequestIsPersistedInDistributedCache()
        {
            // Arrange
            var cache = new Mock<IDistributedCache>();

            await using var server = await CreateServerAsync(
                builder =>
                {
                    builder.Services.AddSingleton(CreateApplicationManager(mock =>
                    {
                        mock.Setup(mock => mock.FindByPostLogoutRedirectUriAsync("http://www.fabrikam.com/path", It.IsAny<CancellationToken>()))
                            .Returns(GetTestApplication());

                        async IAsyncEnumerable<OpenIddictApplication> GetTestApplication()
                        {
                            yield return new OpenIddictApplication();

                            await Task.CompletedTask;
                        }
                    }));


                    builder.Services.AddSingleton(cache.Object);

                    builder
                        .UseAspNetCore()
                        .EnableLogoutRequestCaching()
                        .SetLogoutRequestCachingPolicy(new DistributedCacheEntryOptions
                        {
                            AbsoluteExpirationRelativeToNow = TimeSpan.FromDays(42),
                            SlidingExpiration = TimeSpan.FromSeconds(42)
                        });
                });

            await using var client = await server.CreateClientAsync();

            // Act
            var response = await client.PostAsync(LogoutEndpoint, new OpenIddictRequest
            {
                PostLogoutRedirectUri = "http://www.fabrikam.com/path"
            });

            var identifier = (string?)response[Parameters.RequestId];

            // Assert
            Assert.Single(response.GetParameters());
            Assert.NotNull(identifier);

            cache.Verify(
                mock => mock.SetAsync(
                    $"{Cache.LogoutRequest}{identifier}",
                    It.IsAny<byte[]>(),
                    It.Is<DistributedCacheEntryOptions>(
                        options =>
                        options.AbsoluteExpirationRelativeToNow == TimeSpan.FromDays(42) &&
                        options.SlidingExpiration == TimeSpan.FromSeconds(42)),
                    It.IsAny<CancellationToken>()),
                Times.Once());
        }
    }
}
