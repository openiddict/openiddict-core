/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
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
        private const string AuthorizationEndpoint = "/connect/authorize";

        [Fact(Skip = "The handler responsible of rejecting such requests has not been ported yet.")]
        public async Task ExtractAuthorizationRequest_RequestIdParameterIsRejectedWhenRequestCachingIsDisabled()
        {
            // Arrange
            await using var server = await CreateServerAsync(options => options.EnableDegradedMode());
            await using var client = await server.CreateClientAsync();

            // Act
            var response = await client.PostAsync(AuthorizationEndpoint, new OpenIddictRequest
            {
                RequestId = "EFAF3596-F868-497F-96BB-AA2AD1F8B7E7"
            });

            // Assert
            Assert.Equal(Errors.InvalidRequest, response.Error);
            Assert.Equal(SR.FormatID2028(Parameters.RequestId), response.ErrorDescription);
        }

        [Fact]
        public async Task ExtractAuthorizationRequest_InvalidRequestIdParameterIsRejected()
        {
            // Arrange
            await using var server = await CreateServerAsync(options =>
            {
                options.Services.AddDistributedMemoryCache();

                options.UseAspNetCore()
                       .EnableAuthorizationRequestCaching();
            });

            await using var client = await server.CreateClientAsync();

            // Act
            var response = await client.PostAsync(AuthorizationEndpoint, new OpenIddictRequest
            {
                RequestId = "EFAF3596-F868-497F-96BB-AA2AD1F8B7E7"
            });

            // Assert
            Assert.Equal(Errors.InvalidRequest, response.Error);
            Assert.Equal(SR.FormatID2052(Parameters.RequestId), response.ErrorDescription);
        }

        [Fact]
        public async Task HandleAuthorizationRequest_RequestIsPersistedInDistributedCache()
        {
            // Arrange
            var cache = new Mock<IDistributedCache>();

            await using var server = await CreateServerAsync(
                builder =>
                {
                    builder.Services.AddSingleton(cache.Object);

                    builder
                        .UseAspNetCore()
                        .EnableAuthorizationRequestCaching()
                        .SetAuthorizationRequestCachingPolicy(new DistributedCacheEntryOptions
                        {
                            AbsoluteExpirationRelativeToNow = TimeSpan.FromDays(42),
                            SlidingExpiration = TimeSpan.FromSeconds(42)
                        });
                });

            await using var client = await server.CreateClientAsync();

            // Act
            var response = await client.PostAsync(AuthorizationEndpoint, new OpenIddictRequest
            {
                ClientId = "Fabrikam",
                RedirectUri = "http://www.fabrikam.com/path",
                ResponseType = ResponseTypes.Token
            });

            var identifier = response[Parameters.RequestId]?.Value as string;

            // Assert
            Assert.Single(response.GetParameters());
            Assert.NotNull(identifier);

            cache.Verify(
                mock => mock.SetAsync(
                    $"{Cache.AuthorizationRequest}{identifier}",
                    It.IsAny<byte[]>(),
                    It.Is<DistributedCacheEntryOptions>(
                        options =>
                        options.AbsoluteExpirationRelativeToNow == TimeSpan.FromDays(42) &&
                        options.SlidingExpiration == TimeSpan.FromSeconds(42)),
                    It.IsAny<CancellationToken>()),
                Times.Once());
        }

        [Fact(Skip = "response.AccessToken is null -> System.InvalidOperationException : The authorization request was not handled.")]
        public async Task ApplyAuthorizationResponse_RequestIsRemovedFromDistributedCache()
        {
            // Arrange
            var identifier = "b2ee7815-5579-4ff7-86b0-ba671b939d96";
            var cacheKey = $"{Cache.AuthorizationRequest}{identifier}";
            var request = new OpenIddictRequest
            {
                ClientId = "Fabrikam",
                RedirectUri = "http://www.fabrikam.com/path",
                ResponseType = ResponseTypes.Token
            };

            var securityKey = new SymmetricSecurityKey(new byte[256 / 8]);
            var encryptingCredentials = new EncryptingCredentials(
                securityKey,
                SecurityAlgorithms.Aes256KW,
                SecurityAlgorithms.Aes256CbcHmacSha512);
            var signingCredentials = new SigningCredentials(securityKey, Algorithms.HmacSha256);

            var token = new JsonWebTokenHandler().CreateToken(new SecurityTokenDescriptor
            {
                Audience = "http://localhost/",
                Claims = request.GetParameters().ToDictionary(
                    parameter => parameter.Key,
                    parameter => parameter.Value.Value),
                EncryptingCredentials = encryptingCredentials,
                Issuer = "http://localhost/",
                SigningCredentials = signingCredentials,
                Subject = new ClaimsIdentity(),
                TokenType = OpenIddictServerAspNetCoreConstants.JsonWebTokenTypes.Private.AuthorizationRequest
            });

            var cache = new Mock<IDistributedCache>();
            cache.Setup(mock => mock.GetAsync(cacheKey, It.IsAny<CancellationToken>()))
                 .ReturnsAsync(Encoding.UTF8.GetBytes(token));

            await using var server = await CreateServerAsync(
                builder =>
                {
                    builder.Services.AddSingleton(CreateApplicationManager(mock =>
                    {
                        var application = new OpenIddictApplication();

                        mock.Setup(manager => manager.FindByClientIdAsync("Fabrikam", It.IsAny<CancellationToken>()))
                            .ReturnsAsync(application);

                        mock.Setup(mock => mock.ValidateRedirectUriAsync(application, "http://www.fabrikam.com/path", It.IsAny<CancellationToken>()))
                            .ReturnsAsync(true);
                        
                        mock.Setup(manager => manager.HasClientTypeAsync(application, ClientTypes.Public, It.IsAny<CancellationToken>()))
                            .ReturnsAsync(true);
                    }));

                    builder.AddEncryptionCredentials(encryptingCredentials);
                    builder.AddSigningCredentials(signingCredentials);

                    builder.Services.AddSingleton(cache.Object);

                    builder
                        .UseAspNetCore()
                        .EnableAuthorizationRequestCaching();
                });

            await using var client = await server.CreateClientAsync();

            // Act
            var response = await client.PostAsync(AuthorizationEndpoint, new OpenIddictRequest
            {
                RequestId = identifier
            });

            // Assert
            Assert.NotNull(response.AccessToken);

            cache.Verify(
                mock => mock.RemoveAsync(
                    cacheKey,
                    It.IsAny<CancellationToken>()),
                Times.Once());
        }
    }
}
