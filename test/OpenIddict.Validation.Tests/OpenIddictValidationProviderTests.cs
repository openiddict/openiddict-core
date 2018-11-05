/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using System.Globalization;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using AspNet.Security.OAuth.Validation;
using AspNet.Security.OpenIdConnect.Extensions;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Moq;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using OpenIddict.Abstractions;
using OpenIddict.Core;
using Xunit;

namespace OpenIddict.Validation.Tests
{
    public class OpenIddictValidationProviderTests
    {
        [Fact]
        public async Task DecryptToken_ThrowsAnExceptionWhenTokenManagerIsNotRegistered()
        {
            // Arrange
            var server = CreateResourceServer(builder =>
            {
                builder.Services.RemoveAll(typeof(IOpenIddictTokenManager));
            });

            var client = server.CreateClient();

            var request = new HttpRequestMessage(HttpMethod.Get, "/");
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", "valid-reference-token-id");

            // Act and assert
            var exception = await Assert.ThrowsAsync<InvalidOperationException>(delegate
            {
                return client.SendAsync(request);
            });

            Assert.Equal(new StringBuilder()
                .AppendLine("The core services must be registered when enabling reference tokens support.")
                .Append("To register the OpenIddict core services, reference the 'OpenIddict.Core' package ")
                .Append("and call 'services.AddOpenIddict().AddCore()' from 'ConfigureServices'.")
                .ToString(), exception.Message);
        }

        [Fact]
        public async Task DecryptToken_ReturnsFailedResultForUnknownReferenceToken()
        {
            // Arrange
            var manager = CreateTokenManager(instance =>
            {
                instance.Setup(mock => mock.FindByReferenceIdAsync("invalid-reference-token-id", It.IsAny<CancellationToken>()))
                    .ReturnsAsync(value: null);
            });

            var server = CreateResourceServer(builder =>
            {
                builder.Services.AddSingleton(manager);
            });

            var client = server.CreateClient();

            var request = new HttpRequestMessage(HttpMethod.Get, "/");
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", "invalid-reference-token-id");

            // Act
            var response = await client.SendAsync(request);

            // Assert
            Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);

            Mock.Get(manager).Verify(mock => mock.FindByReferenceIdAsync("invalid-reference-token-id", It.IsAny<CancellationToken>()), Times.Once());
        }

        [Fact]
        public async Task DecryptToken_ReturnsFailedResultForMissingTokenType()
        {
            // Arrange
            var token = new OpenIddictToken();

            var manager = CreateTokenManager(instance =>
            {
                instance.Setup(mock => mock.FindByReferenceIdAsync("valid-reference-token-id", It.IsAny<CancellationToken>()))
                    .ReturnsAsync(token);

                instance.Setup(mock => mock.GetTypeAsync(token, It.IsAny<CancellationToken>()))
                    .Returns(new ValueTask<string>(result: null));
            });

            var server = CreateResourceServer(builder =>
            {
                builder.Services.AddSingleton(manager);
            });

            var client = server.CreateClient();

            var request = new HttpRequestMessage(HttpMethod.Get, "/");
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", "valid-reference-token-id");

            // Act
            var response = await client.SendAsync(request);

            // Assert
            Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);

            Mock.Get(manager).Verify(mock => mock.FindByReferenceIdAsync("valid-reference-token-id", It.IsAny<CancellationToken>()), Times.Once());
            Mock.Get(manager).Verify(mock => mock.GetTypeAsync(token, It.IsAny<CancellationToken>()), Times.Once());
        }

        [Fact]
        public async Task DecryptToken_ReturnsFailedResultForIncompatibleTokenType()
        {
            // Arrange
            var token = new OpenIddictToken();

            var manager = CreateTokenManager(instance =>
            {
                instance.Setup(mock => mock.FindByReferenceIdAsync("valid-reference-token-id", It.IsAny<CancellationToken>()))
                    .ReturnsAsync(token);

                instance.Setup(mock => mock.GetTypeAsync(token, It.IsAny<CancellationToken>()))
                    .Returns(new ValueTask<string>(OpenIddictConstants.TokenTypes.RefreshToken));
            });

            var server = CreateResourceServer(builder =>
            {
                builder.Services.AddSingleton(manager);
            });

            var client = server.CreateClient();

            var request = new HttpRequestMessage(HttpMethod.Get, "/");
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", "valid-reference-token-id");

            // Act
            var response = await client.SendAsync(request);

            // Assert
            Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);

            Mock.Get(manager).Verify(mock => mock.FindByReferenceIdAsync("valid-reference-token-id", It.IsAny<CancellationToken>()), Times.Once());
            Mock.Get(manager).Verify(mock => mock.GetTypeAsync(token, It.IsAny<CancellationToken>()), Times.Once());
        }

        [Fact]
        public async Task DecryptToken_ReturnsFailedResultForNonReferenceToken()
        {
            // Arrange
            var token = new OpenIddictToken();

            var manager = CreateTokenManager(instance =>
            {
                instance.Setup(mock => mock.FindByReferenceIdAsync("valid-reference-token-id", It.IsAny<CancellationToken>()))
                    .ReturnsAsync(token);

                instance.Setup(mock => mock.GetTypeAsync(token, It.IsAny<CancellationToken>()))
                    .Returns(new ValueTask<string>(OpenIddictConstants.TokenTypes.AccessToken));

                instance.Setup(mock => mock.GetPayloadAsync(token, It.IsAny<CancellationToken>()))
                    .Returns(new ValueTask<string>(result: null));
            });

            var server = CreateResourceServer(builder =>
            {
                builder.Services.AddSingleton(manager);
            });

            var client = server.CreateClient();

            var request = new HttpRequestMessage(HttpMethod.Get, "/");
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", "valid-reference-token-id");

            // Act
            var response = await client.SendAsync(request);

            // Assert
            Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);

            Mock.Get(manager).Verify(mock => mock.FindByReferenceIdAsync("valid-reference-token-id", It.IsAny<CancellationToken>()), Times.Once());
            Mock.Get(manager).Verify(mock => mock.GetPayloadAsync(token, It.IsAny<CancellationToken>()), Times.Once());
        }

        [Fact]
        public async Task DecryptToken_ReturnsFailedResultForInvalidReferenceTokenPayload()
        {
            // Arrange
            var token = new OpenIddictToken();

            var format = new Mock<ISecureDataFormat<AuthenticationTicket>>();
            format.Setup(mock => mock.Unprotect("invalid-reference-token-payload"))
                .Returns(value: null);

            var manager = CreateTokenManager(instance =>
            {
                instance.Setup(mock => mock.FindByReferenceIdAsync("valid-reference-token-id", It.IsAny<CancellationToken>()))
                    .ReturnsAsync(token);

                instance.Setup(mock => mock.GetTypeAsync(token, It.IsAny<CancellationToken>()))
                    .Returns(new ValueTask<string>(OpenIddictConstants.TokenTypes.AccessToken));

                instance.Setup(mock => mock.GetPayloadAsync(token, It.IsAny<CancellationToken>()))
                    .Returns(new ValueTask<string>("invalid-reference-token-payload"));
            });

            var server = CreateResourceServer(builder =>
            {
                builder.Services.AddSingleton(manager);
                builder.Configure(options => options.AccessTokenFormat = format.Object);
            });

            var client = server.CreateClient();

            var request = new HttpRequestMessage(HttpMethod.Get, "/");
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", "valid-reference-token-id");

            // Act
            var response = await client.SendAsync(request);

            // Assert
            Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);

            Mock.Get(manager).Verify(mock => mock.FindByReferenceIdAsync("valid-reference-token-id", It.IsAny<CancellationToken>()), Times.Once());
            Mock.Get(manager).Verify(mock => mock.GetPayloadAsync(token, It.IsAny<CancellationToken>()), Times.Once());
            format.Verify(mock => mock.Unprotect("invalid-reference-token-payload"), Times.Once());
        }

        [Fact]
        public async Task ValidateToken_ReturnsFailedResultForInvalidReferenceToken()
        {
            // Arrange
            var token = new OpenIddictToken();

            var format = new Mock<ISecureDataFormat<AuthenticationTicket>>();
            format.Setup(mock => mock.Unprotect("valid-reference-token-payload"))
                .Returns(delegate
                {
                    var identity = new ClaimsIdentity(OpenIddictValidationDefaults.AuthenticationScheme);
                    identity.AddClaim(new Claim(OAuthValidationConstants.Claims.Subject, "Fabrikam"));

                    return new AuthenticationTicket(
                        new ClaimsPrincipal(identity),
                        OpenIddictValidationDefaults.AuthenticationScheme);
                });

            var manager = CreateTokenManager(instance =>
            {
                instance.Setup(mock => mock.FindByReferenceIdAsync("valid-reference-token-id", It.IsAny<CancellationToken>()))
                    .ReturnsAsync(token);

                instance.Setup(mock => mock.GetTypeAsync(token, It.IsAny<CancellationToken>()))
                    .Returns(new ValueTask<string>(OpenIddictConstants.TokenTypes.AccessToken));

                instance.Setup(mock => mock.GetPayloadAsync(token, It.IsAny<CancellationToken>()))
                    .Returns(new ValueTask<string>("valid-reference-token-payload"));

                instance.Setup(mock => mock.GetCreationDateAsync(token, It.IsAny<CancellationToken>()))
                    .Returns(new ValueTask<DateTimeOffset?>(new DateTimeOffset(2018, 01, 01, 00, 00, 00, TimeSpan.Zero)));

                instance.Setup(mock => mock.GetExpirationDateAsync(token, It.IsAny<CancellationToken>()))
                    .Returns(new ValueTask<DateTimeOffset?>(new DateTimeOffset(2918, 01, 01, 00, 00, 00, TimeSpan.Zero)));

                instance.Setup(mock => mock.GetIdAsync(token, It.IsAny<CancellationToken>()))
                    .Returns(new ValueTask<string>("4392E01A-1BC4-4776-8450-EC267C2B708A"));

                instance.Setup(mock => mock.FindByIdAsync("4392E01A-1BC4-4776-8450-EC267C2B708A", It.IsAny<CancellationToken>()))
                    .ReturnsAsync(token);

                instance.Setup(mock => mock.IsValidAsync(token, It.IsAny<CancellationToken>()))
                    .ReturnsAsync(false);
            });

            var server = CreateResourceServer(builder =>
            {
                builder.Services.AddSingleton(manager);
                builder.Configure(options => options.AccessTokenFormat = format.Object);
            });

            var client = server.CreateClient();

            var request = new HttpRequestMessage(HttpMethod.Get, "/ticket");
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", "valid-reference-token-id");

            // Act
            var response = await client.SendAsync(request);

            // Assert
            Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);

            Mock.Get(manager).Verify(mock => mock.FindByReferenceIdAsync("valid-reference-token-id", It.IsAny<CancellationToken>()), Times.Once());
            Mock.Get(manager).Verify(mock => mock.GetPayloadAsync(token, It.IsAny<CancellationToken>()), Times.Once());
            Mock.Get(manager).Verify(mock => mock.GetCreationDateAsync(token, It.IsAny<CancellationToken>()), Times.Once());
            Mock.Get(manager).Verify(mock => mock.GetExpirationDateAsync(token, It.IsAny<CancellationToken>()), Times.Once());
            Mock.Get(manager).Verify(mock => mock.GetIdAsync(token, It.IsAny<CancellationToken>()), Times.Once());
            Mock.Get(manager).Verify(mock => mock.IsValidAsync(token, It.IsAny<CancellationToken>()), Times.Once());
            format.Verify(mock => mock.Unprotect("valid-reference-token-payload"), Times.Once());
        }

        [Fact]
        public async Task ValidateToken_ReturnsValidResultForValidReferenceToken()
        {
            // Arrange
            var token = new OpenIddictToken();

            var format = new Mock<ISecureDataFormat<AuthenticationTicket>>();
            format.Setup(mock => mock.Unprotect("valid-reference-token-payload"))
                .Returns(delegate
                {
                    var identity = new ClaimsIdentity(OpenIddictValidationDefaults.AuthenticationScheme);
                    identity.AddClaim(new Claim(OAuthValidationConstants.Claims.Subject, "Fabrikam"));

                    return new AuthenticationTicket(
                        new ClaimsPrincipal(identity),
                        OpenIddictValidationDefaults.AuthenticationScheme);
                });

            var manager = CreateTokenManager(instance =>
            {
                instance.Setup(mock => mock.FindByReferenceIdAsync("valid-reference-token-id", It.IsAny<CancellationToken>()))
                    .ReturnsAsync(token);

                instance.Setup(mock => mock.GetTypeAsync(token, It.IsAny<CancellationToken>()))
                    .Returns(new ValueTask<string>(OpenIddictConstants.TokenTypes.AccessToken));

                instance.Setup(mock => mock.GetPayloadAsync(token, It.IsAny<CancellationToken>()))
                    .Returns(new ValueTask<string>("valid-reference-token-payload"));

                instance.Setup(mock => mock.GetCreationDateAsync(token, It.IsAny<CancellationToken>()))
                    .Returns(new ValueTask<DateTimeOffset?>(new DateTimeOffset(2018, 01, 01, 00, 00, 00, TimeSpan.Zero)));

                instance.Setup(mock => mock.GetExpirationDateAsync(token, It.IsAny<CancellationToken>()))
                    .Returns(new ValueTask<DateTimeOffset?>(new DateTimeOffset(2918, 01, 01, 00, 00, 00, TimeSpan.Zero)));

                instance.Setup(mock => mock.GetIdAsync(token, It.IsAny<CancellationToken>()))
                    .Returns(new ValueTask<string>("4392E01A-1BC4-4776-8450-EC267C2B708A"));

                instance.Setup(mock => mock.FindByIdAsync("4392E01A-1BC4-4776-8450-EC267C2B708A", It.IsAny<CancellationToken>()))
                    .ReturnsAsync(token);

                instance.Setup(mock => mock.IsValidAsync(token, It.IsAny<CancellationToken>()))
                    .ReturnsAsync(true);
            });

            var server = CreateResourceServer(builder =>
            {
                builder.Services.AddSingleton(manager);
                builder.Configure(options => options.AccessTokenFormat = format.Object);
            });

            var client = server.CreateClient();

            var request = new HttpRequestMessage(HttpMethod.Get, "/ticket");
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", "valid-reference-token-id");

            // Act
            var response = await client.SendAsync(request);

            var ticket = JObject.Parse(await response.Content.ReadAsStringAsync());
            var properties = (from property in ticket.Value<JArray>("Properties")
                              select new
                              {
                                  Name = property.Value<string>("Name"),
                                  Value = property.Value<string>("Value")
                              }).ToDictionary(property => property.Name, property => property.Value);

            // Assert
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);

            Assert.Equal(
                new DateTimeOffset(2018, 01, 01, 00, 00, 00, TimeSpan.Zero),
                DateTimeOffset.Parse(properties[".issued"], CultureInfo.InvariantCulture));
            Assert.Equal(
                new DateTimeOffset(2918, 01, 01, 00, 00, 00, TimeSpan.Zero),
                DateTimeOffset.Parse(properties[".expires"], CultureInfo.InvariantCulture));

            Mock.Get(manager).Verify(mock => mock.FindByReferenceIdAsync("valid-reference-token-id", It.IsAny<CancellationToken>()), Times.Once());
            Mock.Get(manager).Verify(mock => mock.GetPayloadAsync(token, It.IsAny<CancellationToken>()), Times.Once());
            Mock.Get(manager).Verify(mock => mock.GetCreationDateAsync(token, It.IsAny<CancellationToken>()), Times.Once());
            Mock.Get(manager).Verify(mock => mock.GetExpirationDateAsync(token, It.IsAny<CancellationToken>()), Times.Once());
            Mock.Get(manager).Verify(mock => mock.GetIdAsync(token, It.IsAny<CancellationToken>()), Times.Once());
            format.Verify(mock => mock.Unprotect("valid-reference-token-payload"), Times.Once());
        }

        [Fact]
        public async Task ValidateToken_ThrowsAnExceptionWhenAuthorizationManagerIsNotRegistered()
        {
            // Arrange
            var format = new Mock<ISecureDataFormat<AuthenticationTicket>>();
            format.Setup(mock => mock.Unprotect("valid-token"))
                .Returns(delegate
                {
                    var identity = new ClaimsIdentity(OpenIddictValidationDefaults.AuthenticationScheme);
                    identity.AddClaim(new Claim(OAuthValidationConstants.Claims.Subject, "Fabrikam"));

                    return new AuthenticationTicket(
                        new ClaimsPrincipal(identity),
                        OpenIddictValidationDefaults.AuthenticationScheme);
                });

            var server = CreateResourceServer(builder =>
            {
                builder.Services.RemoveAll(typeof(IOpenIddictAuthorizationManager));

                builder.EnableAuthorizationValidation();

                builder.Configure(options =>
                {
                    options.AccessTokenFormat = format.Object;
                    options.UseReferenceTokens = false;
                });
            });

            var client = server.CreateClient();

            var request = new HttpRequestMessage(HttpMethod.Get, "/");
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", "valid-token");

            // Act and assert
            var exception = await Assert.ThrowsAsync<InvalidOperationException>(delegate
            {
                return client.SendAsync(request);
            });

            Assert.Equal(new StringBuilder()
                .AppendLine("The core services must be registered when enabling authorization validation.")
                .Append("To register the OpenIddict core services, reference the 'OpenIddict.Core' package ")
                .Append("and call 'services.AddOpenIddict().AddCore()' from 'ConfigureServices'.")
                .ToString(), exception.Message);
        }

        [Fact]
        public async Task ValidateToken_ReturnsFailedResultForUnknownAuthorization()
        {
            // Arrange
            var format = new Mock<ISecureDataFormat<AuthenticationTicket>>();
            format.Setup(mock => mock.Unprotect("valid-token"))
                .Returns(delegate
                {
                    var identity = new ClaimsIdentity(OpenIddictValidationDefaults.AuthenticationScheme);
                    identity.AddClaim(new Claim(OAuthValidationConstants.Claims.Subject, "Fabrikam"));

                    var ticket = new AuthenticationTicket(
                        new ClaimsPrincipal(identity),
                        OpenIddictValidationDefaults.AuthenticationScheme);

                    ticket.SetProperty(OpenIddictConstants.Properties.InternalAuthorizationId, "5230CBAD-89F9-4C3F-B48C-9253B6FB8620");

                    return ticket;
                });

            var manager = CreateAuthorizationManager(instance =>
            {
                instance.Setup(mock => mock.FindByIdAsync("5230CBAD-89F9-4C3F-B48C-9253B6FB8620", It.IsAny<CancellationToken>()))
                    .ReturnsAsync(value: null);
            });

            var server = CreateResourceServer(builder =>
            {
                builder.Services.AddSingleton(manager);

                builder.EnableAuthorizationValidation();

                builder.Configure(options =>
                {
                    options.AccessTokenFormat = format.Object;
                    options.UseReferenceTokens = false;
                });
            });

            var client = server.CreateClient();

            var request = new HttpRequestMessage(HttpMethod.Get, "/");
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", "valid-token");

            // Act
            var response = await client.SendAsync(request);

            // Assert
            Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);

            Mock.Get(manager).Verify(mock => mock.FindByIdAsync("5230CBAD-89F9-4C3F-B48C-9253B6FB8620", It.IsAny<CancellationToken>()), Times.Once());
        }

        [Fact]
        public async Task ValidateToken_ReturnsFailedResultForInvalidAuthorization()
        {
            // Arrange
            var authorization = new OpenIddictAuthorization();

            var format = new Mock<ISecureDataFormat<AuthenticationTicket>>();
            format.Setup(mock => mock.Unprotect("valid-token"))
                .Returns(delegate
                {
                    var identity = new ClaimsIdentity(OpenIddictValidationDefaults.AuthenticationScheme);
                    identity.AddClaim(new Claim(OAuthValidationConstants.Claims.Subject, "Fabrikam"));

                    var ticket = new AuthenticationTicket(
                        new ClaimsPrincipal(identity),
                        OpenIddictValidationDefaults.AuthenticationScheme);

                    ticket.SetProperty(OpenIddictConstants.Properties.InternalAuthorizationId, "5230CBAD-89F9-4C3F-B48C-9253B6FB8620");

                    return ticket;
                });

            var manager = CreateAuthorizationManager(instance =>
            {
                instance.Setup(mock => mock.FindByIdAsync("5230CBAD-89F9-4C3F-B48C-9253B6FB8620", It.IsAny<CancellationToken>()))
                    .ReturnsAsync(authorization);

                instance.Setup(mock => mock.IsValidAsync(authorization, It.IsAny<CancellationToken>()))
                    .ReturnsAsync(false);
            });

            var server = CreateResourceServer(builder =>
            {
                builder.Services.AddSingleton(manager);

                builder.EnableAuthorizationValidation();

                builder.Configure(options =>
                {
                    options.AccessTokenFormat = format.Object;
                    options.UseReferenceTokens = false;
                });
            });

            var client = server.CreateClient();

            var request = new HttpRequestMessage(HttpMethod.Get, "/");
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", "valid-token");

            // Act
            var response = await client.SendAsync(request);

            // Assert
            Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);

            Mock.Get(manager).Verify(mock => mock.FindByIdAsync("5230CBAD-89F9-4C3F-B48C-9253B6FB8620", It.IsAny<CancellationToken>()), Times.Once());
            Mock.Get(manager).Verify(mock => mock.IsValidAsync(authorization, It.IsAny<CancellationToken>()), Times.Once());
        }

        [Fact]
        public async Task ValidateToken_ReturnsValidResultForValidAuthorization()
        {
            // Arrange
            var authorization = new OpenIddictAuthorization();

            var format = new Mock<ISecureDataFormat<AuthenticationTicket>>();
            format.Setup(mock => mock.Unprotect("valid-token"))
                .Returns(delegate
                {
                    var identity = new ClaimsIdentity(OpenIddictValidationDefaults.AuthenticationScheme);
                    identity.AddClaim(new Claim(OAuthValidationConstants.Claims.Subject, "Fabrikam"));

                    var ticket = new AuthenticationTicket(
                        new ClaimsPrincipal(identity),
                        OpenIddictValidationDefaults.AuthenticationScheme);

                    ticket.SetProperty(OpenIddictConstants.Properties.InternalAuthorizationId, "5230CBAD-89F9-4C3F-B48C-9253B6FB8620");

                    return ticket;
                });

            var manager = CreateAuthorizationManager(instance =>
            {
                instance.Setup(mock => mock.FindByIdAsync("5230CBAD-89F9-4C3F-B48C-9253B6FB8620", It.IsAny<CancellationToken>()))
                    .ReturnsAsync(authorization);

                instance.Setup(mock => mock.IsValidAsync(authorization, It.IsAny<CancellationToken>()))
                    .ReturnsAsync(true);
            });

            var server = CreateResourceServer(builder =>
            {
                builder.Services.AddSingleton(manager);

                builder.EnableAuthorizationValidation();

                builder.Configure(options =>
                {
                    options.AccessTokenFormat = format.Object;
                    options.UseReferenceTokens = false;
                });
            });

            var client = server.CreateClient();

            var request = new HttpRequestMessage(HttpMethod.Get, "/");
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", "valid-token");

            // Act
            var response = await client.SendAsync(request);

            // Assert
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);

            Mock.Get(manager).Verify(mock => mock.FindByIdAsync("5230CBAD-89F9-4C3F-B48C-9253B6FB8620", It.IsAny<CancellationToken>()), Times.Once());
            Mock.Get(manager).Verify(mock => mock.IsValidAsync(authorization, It.IsAny<CancellationToken>()), Times.Once());
        }

        private static TestServer CreateResourceServer(Action<OpenIddictValidationBuilder> configuration = null)
        {
            var builder = new WebHostBuilder();
            builder.UseEnvironment("Testing");

            builder.ConfigureLogging(options => options.AddDebug());

            builder.ConfigureServices(services =>
            {
                services.AddOpenIddict()
                    .AddCore(options =>
                    {
                        options.SetDefaultAuthorizationEntity<OpenIddictAuthorization>();
                        options.SetDefaultTokenEntity<OpenIddictToken>();
                        options.Services.AddSingleton(CreateTokenManager());
                    })

                    .AddValidation(options =>
                    {
                        options.UseReferenceTokens();

                        // Note: overriding the default data protection provider is not necessary for the tests to pass,
                        // but is useful to ensure unnecessary keys are not persisted in testing environments, which also
                        // helps make the unit tests run faster, as no registry or disk access is required in this case.
                        options.UseDataProtectionProvider(new EphemeralDataProtectionProvider());

                        // Run the configuration delegate
                        // registered by the unit tests.
                        configuration?.Invoke(options);
                    });
            });

            builder.Configure(app =>
            {
                app.Map("/ticket", map => map.Run(async context =>
                {
                    var result = await context.AuthenticateAsync(OpenIddictValidationDefaults.AuthenticationScheme);
                    if (result.Principal == null)
                    {
                        await context.ChallengeAsync(OpenIddictValidationDefaults.AuthenticationScheme);

                        return;
                    }

                    context.Response.ContentType = "application/json";

                    // Return the authentication ticket as a JSON object.
                    await context.Response.WriteAsync(JsonConvert.SerializeObject(new
                    {
                        Claims = from claim in result.Principal.Claims
                                 select new { claim.Type, claim.Value },

                        Properties = from property in result.Properties.Items
                                     select new { Name = property.Key, property.Value }
                    }));
                }));

                app.Run(async context =>
                {
                    var result = await context.AuthenticateAsync(OpenIddictValidationDefaults.AuthenticationScheme);
                    if (result.Principal == null)
                    {
                        await context.ChallengeAsync(OpenIddictValidationDefaults.AuthenticationScheme);

                        return;
                    }

                    var subject = result.Principal.FindFirst(OAuthValidationConstants.Claims.Subject)?.Value;
                    if (string.IsNullOrEmpty(subject))
                    {
                        await context.ChallengeAsync(OpenIddictValidationDefaults.AuthenticationScheme);

                        return;
                    }

                    await context.Response.WriteAsync(subject);
                });
            });

            return new TestServer(builder);
        }

        private static OpenIddictAuthorizationManager<OpenIddictAuthorization> CreateAuthorizationManager(
            Action<Mock<OpenIddictAuthorizationManager<OpenIddictAuthorization>>> configuration = null)
        {
            var manager = new Mock<OpenIddictAuthorizationManager<OpenIddictAuthorization>>(
                Mock.Of<IOpenIddictAuthorizationCache<OpenIddictAuthorization>>(),
                Mock.Of<IOpenIddictAuthorizationStoreResolver>(),
                Mock.Of<ILogger<OpenIddictAuthorizationManager<OpenIddictAuthorization>>>(),
                Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>(mock =>
                    mock.CurrentValue == new OpenIddictCoreOptions()));

            configuration?.Invoke(manager);

            return manager.Object;
        }

        private static OpenIddictTokenManager<OpenIddictToken> CreateTokenManager(
            Action<Mock<OpenIddictTokenManager<OpenIddictToken>>> configuration = null)
        {
            var manager = new Mock<OpenIddictTokenManager<OpenIddictToken>>(
                Mock.Of<IOpenIddictTokenCache<OpenIddictToken>>(),
                Mock.Of<IOpenIddictTokenStoreResolver>(),
                Mock.Of<ILogger<OpenIddictTokenManager<OpenIddictToken>>>(),
                Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>(mock =>
                    mock.CurrentValue == new OpenIddictCoreOptions()));

            configuration?.Invoke(manager);

            return manager.Object;
        }

        public class OpenIddictAuthorization { }

        public class OpenIddictToken { }
    }
}
