/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using System.Collections.Immutable;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using AspNet.Security.OpenIdConnect.Client;
using AspNet.Security.OpenIdConnect.Primitives;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.DependencyInjection;
using Moq;
using OpenIddict.Abstractions;
using Xunit;

namespace OpenIddict.Server.Internal.Tests
{
    public partial class OpenIddictServerProviderTests
    {
        [Fact]
        public async Task ExtractLogoutRequest_RequestIdParameterIsRejectedWhenRequestCachingIsDisabled()
        {
            // Arrange
            var server = CreateAuthorizationServer();

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync(LogoutEndpoint, new OpenIdConnectRequest
            {
                RequestId = "EFAF3596-F868-497F-96BB-AA2AD1F8B7E7"
            });

            // Assert
            Assert.Equal(OpenIddictConstants.Errors.InvalidRequest, response.Error);
            Assert.Equal("The 'request_id' parameter is not supported.", response.ErrorDescription);
        }

        [Fact]
        public async Task ExtractLogoutRequest_InvalidRequestIdParameterIsRejected()
        {
            // Arrange
            var server = CreateAuthorizationServer(builder =>
            {
                builder.Services.AddDistributedMemoryCache();

                builder.EnableRequestCaching();
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync(LogoutEndpoint, new OpenIdConnectRequest
            {
                RequestId = "EFAF3596-F868-497F-96BB-AA2AD1F8B7E7"
            });

            // Assert
            Assert.Equal(OpenIddictConstants.Errors.InvalidRequest, response.Error);
            Assert.Equal("The specified 'request_id' parameter is invalid.", response.ErrorDescription);
        }

        [Theory]
        [InlineData("/path", "The 'post_logout_redirect_uri' parameter must be a valid absolute URL.")]
        [InlineData("/tmp/file.xml", "The 'post_logout_redirect_uri' parameter must be a valid absolute URL.")]
        [InlineData("C:\\tmp\\file.xml", "The 'post_logout_redirect_uri' parameter must be a valid absolute URL.")]
        [InlineData("http://www.fabrikam.com/path#param=value", "The 'post_logout_redirect_uri' parameter must not include a fragment.")]
        public async Task ValidateLogoutRequest_RequestIsRejectedWhenRedirectUriIsInvalid(string address, string message)
        {
            // Arrange
            var server = CreateAuthorizationServer();

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync(LogoutEndpoint, new OpenIdConnectRequest
            {
                PostLogoutRedirectUri = address
            });

            // Assert
            Assert.Equal(OpenIddictConstants.Errors.InvalidRequest, response.Error);
            Assert.Equal(message, response.ErrorDescription);
        }

        [Fact]
        public async Task ValidateLogoutRequest_RequestIsRejectedWhenRedirectUriIsUnknown()
        {
            // Arrange
            var manager = CreateApplicationManager(instance =>
            {
                instance.Setup(mock => mock.FindByPostLogoutRedirectUriAsync("http://www.fabrikam.com/path", It.IsAny<CancellationToken>()))
                    .ReturnsAsync(ImmutableArray.Create<OpenIddictApplication>());
            });

            var server = CreateAuthorizationServer(builder =>
            {
                builder.Services.AddSingleton(manager);
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync(LogoutEndpoint, new OpenIdConnectRequest
            {
                PostLogoutRedirectUri = "http://www.fabrikam.com/path"
            });

            // Assert
            Assert.Equal(OpenIddictConstants.Errors.InvalidRequest, response.Error);
            Assert.Equal("The specified 'post_logout_redirect_uri' parameter is not valid.", response.ErrorDescription);

            Mock.Get(manager).Verify(mock => mock.FindByPostLogoutRedirectUriAsync("http://www.fabrikam.com/path", It.IsAny<CancellationToken>()), Times.Once());
        }

        [Fact]
        public async Task ValidateLogoutRequest_RequestIsRejectedWhenApplicationHasNoLogoutPermission()
        {
            // Arrange
            var application = new OpenIddictApplication();

            var manager = CreateApplicationManager(instance =>
            {
                instance.Setup(mock => mock.FindByPostLogoutRedirectUriAsync("http://www.fabrikam.com/path", It.IsAny<CancellationToken>()))
                    .ReturnsAsync(ImmutableArray.Create(application));

                instance.Setup(mock => mock.HasPermissionAsync(application,
                    OpenIddictConstants.Permissions.Endpoints.Logout, It.IsAny<CancellationToken>()))
                    .ReturnsAsync(false);
            });

            var server = CreateAuthorizationServer(builder =>
            {
                builder.Services.AddSingleton(manager);

                builder.Configure(options => options.IgnoreEndpointPermissions = false);
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync(LogoutEndpoint, new OpenIdConnectRequest
            {
                PostLogoutRedirectUri = "http://www.fabrikam.com/path"
            });

            // Assert
            Assert.Equal(OpenIddictConstants.Errors.InvalidRequest, response.Error);
            Assert.Equal("The specified 'post_logout_redirect_uri' parameter is not valid.", response.ErrorDescription);

            Mock.Get(manager).Verify(mock => mock.HasPermissionAsync(application,
                OpenIddictConstants.Permissions.Endpoints.Logout, It.IsAny<CancellationToken>()), Times.Once());
        }

        [Fact]
        public async Task HandleLogoutRequest_RequestIsPersistedInDistributedCache()
        {
            // Arrange
            var cache = new Mock<IDistributedCache>();
            var generator = new Mock<RandomNumberGenerator>();

            var server = CreateAuthorizationServer(builder =>
            {
                builder.Services.AddSingleton(CreateApplicationManager(instance =>
                {
                    instance.Setup(mock => mock.FindByPostLogoutRedirectUriAsync("http://www.fabrikam.com/path", It.IsAny<CancellationToken>()))
                        .ReturnsAsync(ImmutableArray.Create(new OpenIddictApplication()));
                }));

                builder.Services.AddSingleton(cache.Object);

                builder.EnableRequestCaching();

                builder.SetRequestCachingPolicy(new DistributedCacheEntryOptions
                {
                    AbsoluteExpirationRelativeToNow = TimeSpan.FromDays(42),
                    SlidingExpiration = TimeSpan.FromSeconds(42)
                });

                builder.Configure(options => options.RandomNumberGenerator = generator.Object);
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync(LogoutEndpoint, new OpenIdConnectRequest
            {
                PostLogoutRedirectUri = "http://www.fabrikam.com/path"
            });

            var identifier = (string) response[OpenIddictConstants.Parameters.RequestId];

            // Assert
            Assert.Single(response.GetParameters());
            Assert.NotNull(identifier);

            cache.Verify(mock => mock.SetAsync(
                OpenIddictConstants.Environment.LogoutRequest + identifier,
                It.IsAny<byte[]>(),
                It.Is<DistributedCacheEntryOptions>(options =>
                    options.AbsoluteExpirationRelativeToNow == TimeSpan.FromDays(42) &&
                    options.SlidingExpiration == TimeSpan.FromSeconds(42)),
                It.IsAny<CancellationToken>()), Times.Once());

            generator.Verify(mock => mock.GetBytes(It.Is<byte[]>(bytes => bytes.Length == 256 / 8)), Times.Once());
        }

        [Fact]
        public async Task HandleLogoutRequest_RequestsAreNotHandledLocally()
        {
            // Arrange
            var server = CreateAuthorizationServer(builder =>
            {
                builder.Services.AddSingleton(CreateApplicationManager(instance =>
                {
                    instance.Setup(mock => mock.FindByPostLogoutRedirectUriAsync("http://www.fabrikam.com/path", It.IsAny<CancellationToken>()))
                        .ReturnsAsync(ImmutableArray.Create(new OpenIddictApplication()));
                }));
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync(LogoutEndpoint, new OpenIdConnectRequest
            {
                PostLogoutRedirectUri = "http://www.fabrikam.com/path",
                State = "af0ifjsldkj"
            });

            // Assert
            Assert.Equal("af0ifjsldkj", response.State);
        }

        [Fact]
        public async Task ApplyLogoutResponse_SupportsNullRequests()
        {
            // Note: when an invalid HTTP verb is used, the OpenID Connect server handler refuses to extract the request
            // and immediately returns an error. In this specific case, ApplyLogoutResponseContext.Request is null
            // and this test ensures ApplyLogoutResponse can safely handle cases where the request is unavailable.

            // Arrange
            var server = CreateAuthorizationServer(builder =>
            {
                builder.EnableRequestCaching();
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.SendAsync(HttpMethods.Put, LogoutEndpoint, new OpenIdConnectRequest());

            // Assert
            Assert.Equal(OpenIddictConstants.Errors.InvalidRequest, response.Error);
            Assert.Equal("The specified HTTP method is not valid.", response.ErrorDescription);
        }

        [Fact]
        public async Task ApplyLogoutResponse_ErroredRequestIsNotHandledLocallyWhenStatusCodeMiddlewareIsEnabled()
        {
            // Arrange
            var server = CreateAuthorizationServer(builder =>
            {
                builder.Services.AddSingleton(CreateApplicationManager(instance =>
                {
                    instance.Setup(mock => mock.FindByPostLogoutRedirectUriAsync("http://www.fabrikam.com/path", It.IsAny<CancellationToken>()))
                        .ReturnsAsync(ImmutableArray.Create(new OpenIddictApplication()));
                }));

                builder.EnableAuthorizationEndpoint("/logout-status-code-middleware");
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync("/logout-status-code-middleware", new OpenIdConnectRequest
            {
                PostLogoutRedirectUri = "http://www.fabrikam.com/path"
            });

            // Assert
            Assert.Equal(OpenIddictConstants.Errors.InvalidRequest, (string) response["error_custom"]);
        }
    }
}
