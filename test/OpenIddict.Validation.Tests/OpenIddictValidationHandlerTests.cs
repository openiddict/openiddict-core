/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Threading.Tasks;
using AspNet.Security.OAuth.Validation;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Moq;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using OpenIddict.Abstractions;
using OpenIddict.Core;
using OpenIddict.Models;
using Xunit;

namespace OpenIddict.Validation.Tests
{
    public class OpenIddictValidationHandlerTests
    {
        [Fact]
        public async Task HandleAuthenticateAsync_InvalidTokenCausesInvalidAuthentication()
        {
            // Arrange
            var server = CreateResourceServer();
            var client = server.CreateClient();

            var request = new HttpRequestMessage(HttpMethod.Get, "/");
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", "invalid-token");

            // Act
            var response = await client.SendAsync(request);

            // Assert
            Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        }

        [Fact]
        public async Task HandleAuthenticateAsync_ValidTokenAllowsSuccessfulAuthentication()
        {
            // Arrange
            var server = CreateResourceServer();
            var client = server.CreateClient();

            var request = new HttpRequestMessage(HttpMethod.Get, "/");
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", "valid-token");

            // Act
            var response = await client.SendAsync(request);

            // Assert
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            Assert.Equal("Fabrikam", await response.Content.ReadAsStringAsync());
        }

        [Fact]
        public async Task HandleAuthenticateAsync_MissingAudienceCausesInvalidAuthentication()
        {
            // Arrange
            var server = CreateResourceServer(builder =>
            {
                builder.AddAudiences("http://www.fabrikam.com/");
            });

            var client = server.CreateClient();

            var request = new HttpRequestMessage(HttpMethod.Get, "/");
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", "valid-token");

            // Act
            var response = await client.SendAsync(request);

            // Assert
            Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        }

        [Fact]
        public async Task HandleAuthenticateAsync_InvalidAudienceCausesInvalidAuthentication()
        {
            // Arrange
            var server = CreateResourceServer(builder =>
            {
                builder.AddAudiences("http://www.fabrikam.com/");
            });

            var client = server.CreateClient();

            var request = new HttpRequestMessage(HttpMethod.Get, "/");
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", "valid-token-with-single-audience");

            // Act
            var response = await client.SendAsync(request);

            // Assert
            Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        }

        [Fact]
        public async Task HandleAuthenticateAsync_ValidAudienceAllowsSuccessfulAuthentication()
        {
            // Arrange
            var server = CreateResourceServer(builder =>
            {
                builder.AddAudiences("http://www.fabrikam.com/");
            });

            var client = server.CreateClient();

            var request = new HttpRequestMessage(HttpMethod.Get, "/");
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", "valid-token-with-multiple-audiences");

            // Act
            var response = await client.SendAsync(request);

            // Assert
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            Assert.Equal("Fabrikam", await response.Content.ReadAsStringAsync());
        }

        [Fact]
        public async Task HandleAuthenticateAsync_AnyMatchingAudienceCausesSuccessfulAuthentication()
        {
            // Arrange
            var server = CreateResourceServer(builder =>
            {
                builder.AddAudiences("http://www.contoso.com/");
                builder.AddAudiences("http://www.fabrikam.com/");
            });

            var client = server.CreateClient();

            var request = new HttpRequestMessage(HttpMethod.Get, "/");
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", "valid-token-with-single-audience");

            // Act
            var response = await client.SendAsync(request);

            // Assert
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            Assert.Equal("Fabrikam", await response.Content.ReadAsStringAsync());
        }

        [Fact]
        public async Task HandleAuthenticateAsync_MultipleMatchingAudienceCausesSuccessfulAuthentication()
        {
            // Arrange
            var server = CreateResourceServer(builder =>
            {
                builder.AddAudiences("http://www.contoso.com/");
                builder.AddAudiences("http://www.fabrikam.com/");
            });

            var client = server.CreateClient();

            var request = new HttpRequestMessage(HttpMethod.Get, "/");
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", "valid-token-with-multiple-audiences");

            // Act
            var response = await client.SendAsync(request);

            // Assert
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            Assert.Equal("Fabrikam", await response.Content.ReadAsStringAsync());
        }

        [Fact]
        public async Task HandleAuthenticateAsync_ExpiredTicketCausesInvalidAuthentication()
        {
            // Arrange
            var server = CreateResourceServer();
            var client = server.CreateClient();

            var request = new HttpRequestMessage(HttpMethod.Get, "/");
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", "expired-token");

            // Act
            var response = await client.SendAsync(request);

            // Assert
            Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        }

        [Fact]
        public async Task HandleAuthenticateAsync_AuthenticationTicketContainsRequiredClaims()
        {
            // Arrange
            var server = CreateResourceServer();
            var client = server.CreateClient();

            var request = new HttpRequestMessage(HttpMethod.Get, "/ticket");
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", "valid-token-with-scopes");

            // Act
            var response = await client.SendAsync(request);

            var ticket = JObject.Parse(await response.Content.ReadAsStringAsync());
            var claims = from claim in ticket.Value<JArray>("Claims")
                         select new
                         {
                             Type = claim.Value<string>(nameof(Claim.Type)),
                             Value = claim.Value<string>(nameof(Claim.Value))
                         };

            // Assert
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);

            Assert.Contains(claims, claim => claim.Type == OAuthValidationConstants.Claims.Subject &&
                                             claim.Value == "Fabrikam");

            Assert.Contains(claims, claim => claim.Type == OAuthValidationConstants.Claims.Scope &&
                                             claim.Value == "C54A8F5E-0387-43F4-BA43-FD4B50DC190D");

            Assert.Contains(claims, claim => claim.Type == OAuthValidationConstants.Claims.Scope &&
                                             claim.Value == "5C57E3BD-9EFB-4224-9AB8-C8C5E009FFD7");
        }

        [Fact]
        public async Task HandleAuthenticateAsync_AuthenticationTicketContainsRequiredProperties()
        {
            // Arrange
            var server = CreateResourceServer(builder =>
            {
                builder.Configure(options => options.SaveToken = true);
            });

            var client = server.CreateClient();

            var request = new HttpRequestMessage(HttpMethod.Get, "/ticket");
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", "valid-token");

            // Act
            var response = await client.SendAsync(request);

            var ticket = JObject.Parse(await response.Content.ReadAsStringAsync());
            var properties = from claim in ticket.Value<JArray>("Properties")
                             select new
                             {
                                 Name = claim.Value<string>("Name"),
                                 Value = claim.Value<string>("Value")
                             };

            // Assert
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);

            Assert.Contains(properties, property => property.Name == ".Token.access_token" &&
                                                    property.Value == "valid-token");
        }

        [Fact]
        public async Task HandleAuthenticateAsync_InvalidReplacedTokenCausesInvalidAuthentication()
        {
            // Arrange
            var server = CreateResourceServer(builder =>
            {
                builder.Configure(options => options.Events.OnRetrieveToken = context =>
                {
                    context.Token = "invalid-token";

                    return Task.FromResult(0);
                });
            });

            var client = server.CreateClient();

            var request = new HttpRequestMessage(HttpMethod.Get, "/");
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", "valid-token");

            // Act
            var response = await client.SendAsync(request);

            // Assert
            Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        }

        [Fact]
        public async Task HandleAuthenticateAsync_ValidReplacedTokenCausesSuccessfulAuthentication()
        {
            // Arrange
            var server = CreateResourceServer(builder =>
            {
                builder.Configure(options => options.Events.OnRetrieveToken = context =>
                {
                    context.Token = "valid-token";

                    return Task.FromResult(0);
                });
            });

            var client = server.CreateClient();

            var request = new HttpRequestMessage(HttpMethod.Get, "/");
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", "invalid-token");

            // Act
            var response = await client.SendAsync(request);

            // Assert
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            Assert.Equal("Fabrikam", await response.Content.ReadAsStringAsync());
        }

        [Fact]
        public async Task HandleAuthenticateAsync_FailFromReceiveTokenCausesInvalidAuthentication()
        {
            // Arrange
            var server = CreateResourceServer(builder =>
            {
                builder.Configure(options => options.Events.OnRetrieveToken = context =>
                {
                    context.Fail(new Exception());

                    return Task.FromResult(0);
                });
            });

            var client = server.CreateClient();

            var request = new HttpRequestMessage(HttpMethod.Get, "/");
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", "valid-token");

            // Act
            var response = await client.SendAsync(request);

            // Assert
            Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        }

        [Fact]
        public async Task HandleAuthenticateAsync_NoResultFromReceiveTokenCauseInvalidAuthentication()
        {
            // Arrange
            var server = CreateResourceServer(builder =>
            {
                builder.Configure(options => options.Events.OnRetrieveToken = context =>
                {
                    context.NoResult();

                    return Task.FromResult(0);
                });
            });

            var client = server.CreateClient();

            var request = new HttpRequestMessage(HttpMethod.Get, "/");
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", "valid-token");

            // Act
            var response = await client.SendAsync(request);

            // Assert
            Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        }

        [Fact]
        public async Task HandleAuthenticateAsync_SuccessFromReceiveTokenCauseSuccessfulAuthentication()
        {
            // Arrange
            var server = CreateResourceServer(builder =>
            {
                builder.Configure(options => options.Events.OnRetrieveToken = context =>
                {
                    var identity = new ClaimsIdentity(OAuthValidationDefaults.AuthenticationScheme);
                    identity.AddClaim(new Claim(OAuthValidationConstants.Claims.Subject, "Fabrikam"));

                    context.Principal = new ClaimsPrincipal(identity);
                    context.Success();

                    return Task.FromResult(0);
                });
            });

            var client = server.CreateClient();

            var request = new HttpRequestMessage(HttpMethod.Get, "/");
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", "invalid-token");

            // Act
            var response = await client.SendAsync(request);

            // Assert
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            Assert.Equal("Fabrikam", await response.Content.ReadAsStringAsync());
        }

        [Fact]
        public async Task HandleAuthenticateAsync_FailFromValidateTokenCausesInvalidAuthentication()
        {
            // Arrange
            var server = CreateResourceServer(builder =>
            {
                builder.Configure(options => options.Events.OnValidateToken = context =>
                {
                    context.Fail(new Exception());

                    return Task.FromResult(0);
                });
            });

            var client = server.CreateClient();

            var request = new HttpRequestMessage(HttpMethod.Get, "/");
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", "valid-token");

            // Act
            var response = await client.SendAsync(request);

            // Assert
            Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        }

        [Fact]
        public async Task HandleAuthenticateAsync_NoResultFromValidateTokenCauseInvalidAuthentication()
        {
            // Arrange
            var server = CreateResourceServer(builder =>
            {
                builder.Configure(options => options.Events.OnValidateToken = context =>
                {
                    context.NoResult();

                    return Task.FromResult(0);
                });
            });

            var client = server.CreateClient();

            var request = new HttpRequestMessage(HttpMethod.Get, "/");
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", "valid-token");

            // Act
            var response = await client.SendAsync(request);

            // Assert
            Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        }

        [Fact]
        public async Task HandleAuthenticateAsync_SuccessFromValidateTokenCauseSuccessfulAuthentication()
        {
            // Arrange
            var server = CreateResourceServer(builder =>
            {
                builder.Configure(options => options.Events.OnValidateToken = context =>
                {
                    var identity = new ClaimsIdentity(OAuthValidationDefaults.AuthenticationScheme);
                    identity.AddClaim(new Claim(OAuthValidationConstants.Claims.Subject, "Contoso"));

                    context.Principal = new ClaimsPrincipal(identity);
                    context.Success();

                    return Task.FromResult(0);
                });
            });

            var client = server.CreateClient();

            var request = new HttpRequestMessage(HttpMethod.Get, "/");
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", "valid-token");

            // Act
            var response = await client.SendAsync(request);

            // Assert
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            Assert.Equal("Contoso", await response.Content.ReadAsStringAsync());
        }

        [Fact]
        public async Task HandleUnauthorizedAsync_ErrorDetailsAreResolvedFromChallengeContext()
        {
            // Arrange
            var server = CreateResourceServer(builder =>
            {
                builder.RemoveErrorDetails();
                builder.SetRealm("global_realm");

                builder.Configure(options => options.Events.OnApplyChallenge = context =>
                {
                    // Assert
                    Assert.Equal("custom_error", context.Error);
                    Assert.Equal("custom_error_description", context.ErrorDescription);
                    Assert.Equal("custom_error_uri", context.ErrorUri);
                    Assert.Equal("custom_realm", context.Realm);
                    Assert.Equal("custom_scope", context.Scope);

                    return Task.FromResult(0);
                });
            });

            var client = server.CreateClient();

            // Act
            var response = await client.GetAsync("/challenge");

            // Assert
            Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
            Assert.Equal(@"Bearer realm=""custom_realm"", error=""custom_error"", error_description=""custom_error_description"", " +
                         @"error_uri=""custom_error_uri"", scope=""custom_scope""", response.Headers.WwwAuthenticate.ToString());
        }

        [Theory]
        [InlineData("invalid-token", OAuthValidationConstants.Errors.InvalidToken, "The access token is not valid.")]
        [InlineData("expired-token", OAuthValidationConstants.Errors.InvalidToken, "The access token is no longer valid.")]
        public async Task HandleUnauthorizedAsync_ErrorDetailsAreInferredFromAuthenticationFailure(
            string token, string error, string description)
        {
            // Arrange
            var server = CreateResourceServer();
            var client = server.CreateClient();

            var request = new HttpRequestMessage(HttpMethod.Get, "/");
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);

            // Act
            var response = await client.SendAsync(request);

            // Assert
            Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
            Assert.Equal($@"Bearer error=""{error}"", error_description=""{description}""",
                         response.Headers.WwwAuthenticate.ToString());
        }

        [Fact]
        public async Task HandleUnauthorizedAsync_ApplyChallenge_AllowsHandlingResponse()
        {
            // Arrange
            var server = CreateResourceServer(builder =>
            {
                builder.Configure(options => options.Events.OnApplyChallenge = context =>
                {
                    context.HandleResponse();
                    context.HttpContext.Response.Headers["X-Custom-Authentication-Header"] = "Bearer";

                    return Task.FromResult(0);
                });
            });

            var client = server.CreateClient();

            // Act
            var response = await client.GetAsync("/challenge");

            // Assert
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            Assert.Empty(response.Headers.WwwAuthenticate);
            Assert.Equal(new[] { "Bearer" }, response.Headers.GetValues("X-Custom-Authentication-Header"));
        }

        [Theory]
        [InlineData(null, null, null, null, null, "Bearer")]
        [InlineData("custom_error", null, null, null, null, @"Bearer error=""custom_error""")]
        [InlineData(null, "custom_error_description", null, null, null, @"Bearer error_description=""custom_error_description""")]
        [InlineData(null, null, "custom_error_uri", null, null, @"Bearer error_uri=""custom_error_uri""")]
        [InlineData(null, null, null, "custom_realm", null, @"Bearer realm=""custom_realm""")]
        [InlineData(null, null, null, null, "custom_scope", @"Bearer scope=""custom_scope""")]
        [InlineData("custom_error", "custom_error_description", "custom_error_uri", "custom_realm", "custom_scope",
                    @"Bearer realm=""custom_realm"", error=""custom_error"", " +
                    @"error_description=""custom_error_description"", " +
                    @"error_uri=""custom_error_uri"", scope=""custom_scope""")]
        public async Task HandleUnauthorizedAsync_ReturnsExpectedWwwAuthenticateHeader(
            string error, string description, string uri, string realm, string scope, string header)
        {
            // Arrange
            var server = CreateResourceServer(builder =>
            {
                builder.Configure(options => options.Events.OnApplyChallenge = context =>
                {
                    context.Error = error;
                    context.ErrorDescription = description;
                    context.ErrorUri = uri;
                    context.Realm = realm;
                    context.Scope = scope;

                    return Task.FromResult(0);
                });
            });

            var client = server.CreateClient();

            // Act
            var response = await client.GetAsync("/challenge");

            // Assert
            Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
            Assert.Equal(header, response.Headers.WwwAuthenticate.ToString());
        }

        private static TestServer CreateResourceServer(Action<OpenIddictValidationBuilder> configuration = null)
        {
            var format = new Mock<ISecureDataFormat<AuthenticationTicket>>(MockBehavior.Strict);

            format.Setup(mock => mock.Unprotect(It.Is<string>(token => token == "invalid-token")))
                  .Returns(value: null);

            format.Setup(mock => mock.Unprotect(It.Is<string>(token => token == "valid-token")))
                  .Returns(delegate
                  {
                      var identity = new ClaimsIdentity(OAuthValidationDefaults.AuthenticationScheme);
                      identity.AddClaim(new Claim(OAuthValidationConstants.Claims.Subject, "Fabrikam"));

                      var properties = new AuthenticationProperties();

                      return new AuthenticationTicket(new ClaimsPrincipal(identity),
                          properties, OAuthValidationDefaults.AuthenticationScheme);
                  });

            format.Setup(mock => mock.Unprotect(It.Is<string>(token => token == "valid-token-with-scopes")))
                  .Returns(delegate
                  {
                      var identity = new ClaimsIdentity(OAuthValidationDefaults.AuthenticationScheme);
                      identity.AddClaim(new Claim(OAuthValidationConstants.Claims.Subject, "Fabrikam"));

                      var properties = new AuthenticationProperties();
                      properties.Items[OAuthValidationConstants.Properties.Scopes] =
                        @"[""C54A8F5E-0387-43F4-BA43-FD4B50DC190D"",""5C57E3BD-9EFB-4224-9AB8-C8C5E009FFD7""]";

                      return new AuthenticationTicket(new ClaimsPrincipal(identity),
                          properties, OAuthValidationDefaults.AuthenticationScheme);
                  });

            format.Setup(mock => mock.Unprotect(It.Is<string>(token => token == "valid-token-with-single-audience")))
                  .Returns(delegate
                  {
                      var identity = new ClaimsIdentity(OAuthValidationDefaults.AuthenticationScheme);
                      identity.AddClaim(new Claim(OAuthValidationConstants.Claims.Subject, "Fabrikam"));

                      var properties = new AuthenticationProperties(new Dictionary<string, string>
                      {
                          [OAuthValidationConstants.Properties.Audiences] = @"[""http://www.contoso.com/""]"
                      });

                      return new AuthenticationTicket(new ClaimsPrincipal(identity),
                          properties, OAuthValidationDefaults.AuthenticationScheme);
                  });

            format.Setup(mock => mock.Unprotect(It.Is<string>(token => token == "valid-token-with-multiple-audiences")))
                  .Returns(delegate
                  {
                      var identity = new ClaimsIdentity(OAuthValidationDefaults.AuthenticationScheme);
                      identity.AddClaim(new Claim(OAuthValidationConstants.Claims.Subject, "Fabrikam"));

                      var properties = new AuthenticationProperties(new Dictionary<string, string>
                      {
                          [OAuthValidationConstants.Properties.Audiences] = @"[""http://www.contoso.com/"",""http://www.fabrikam.com/""]"
                      });

                      return new AuthenticationTicket(new ClaimsPrincipal(identity),
                          properties, OAuthValidationDefaults.AuthenticationScheme);
                  });

            format.Setup(mock => mock.Unprotect(It.Is<string>(token => token == "expired-token")))
                  .Returns(delegate
                  {
                      var identity = new ClaimsIdentity(OAuthValidationDefaults.AuthenticationScheme);
                      identity.AddClaim(new Claim(OAuthValidationConstants.Claims.Subject, "Fabrikam"));

                      var properties = new AuthenticationProperties();
                      properties.ExpiresUtc = DateTimeOffset.UtcNow - TimeSpan.FromDays(1);

                      return new AuthenticationTicket(new ClaimsPrincipal(identity),
                          properties, OAuthValidationDefaults.AuthenticationScheme);
                  });

            var builder = new WebHostBuilder();
            builder.UseEnvironment("Testing");

            builder.ConfigureLogging(options => options.AddDebug());

            builder.ConfigureServices(services =>
            {
                services.AddOpenIddict()
                    .AddCore(options =>
                    {
                        // Replace the default OpenIddict managers.
                        options.Services.AddSingleton(CreateApplicationManager());
                        options.Services.AddSingleton(CreateAuthorizationManager());
                        options.Services.AddSingleton(CreateScopeManager());
                        options.Services.AddSingleton(CreateTokenManager());
                    })

                    .AddValidation(options =>
                    {
                        options.Configure(settings => settings.AccessTokenFormat = format.Object);

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
                    var result = await context.AuthenticateAsync(OAuthValidationDefaults.AuthenticationScheme);
                    if (result.Principal == null)
                    {
                        await context.ChallengeAsync();

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

                app.Map("/challenge", map => map.Run(context =>
                {
                    var properties = new AuthenticationProperties(new Dictionary<string, string>
                    {
                        [OAuthValidationConstants.Properties.Error] = "custom_error",
                        [OAuthValidationConstants.Properties.ErrorDescription] = "custom_error_description",
                        [OAuthValidationConstants.Properties.ErrorUri] = "custom_error_uri",
                        [OAuthValidationConstants.Properties.Realm] = "custom_realm",
                        [OAuthValidationConstants.Properties.Scope] = "custom_scope",
                    });

                    return context.ChallengeAsync(OAuthValidationDefaults.AuthenticationScheme, properties);
                }));

                app.Run(async context =>
                {
                    var result = await context.AuthenticateAsync(OAuthValidationDefaults.AuthenticationScheme);
                    if (result.Principal == null)
                    {
                        await context.ChallengeAsync(OAuthValidationDefaults.AuthenticationScheme);

                        return;
                    }

                    var subject = result.Principal.FindFirst(OAuthValidationConstants.Claims.Subject)?.Value;
                    if (string.IsNullOrEmpty(subject))
                    {
                        await context.ChallengeAsync(OAuthValidationDefaults.AuthenticationScheme);

                        return;
                    }

                    await context.Response.WriteAsync(subject);
                });
            });

            return new TestServer(builder);
        }
        
        private static OpenIddictApplicationManager<OpenIddictApplication> CreateApplicationManager(
            Action<Mock<OpenIddictApplicationManager<OpenIddictApplication>>> configuration = null)
        {
            var manager = new Mock<OpenIddictApplicationManager<OpenIddictApplication>>(
                Mock.Of<IOpenIddictApplicationStoreResolver>(),
                Mock.Of<ILogger<OpenIddictApplicationManager<OpenIddictApplication>>>(),
                Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>());

            configuration?.Invoke(manager);

            return manager.Object;
        }

        private static OpenIddictAuthorizationManager<OpenIddictAuthorization> CreateAuthorizationManager(
            Action<Mock<OpenIddictAuthorizationManager<OpenIddictAuthorization>>> configuration = null)
        {
            var manager = new Mock<OpenIddictAuthorizationManager<OpenIddictAuthorization>>(
                Mock.Of<IOpenIddictAuthorizationStoreResolver>(),
                Mock.Of<ILogger<OpenIddictAuthorizationManager<OpenIddictAuthorization>>>(),
                Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>());

            configuration?.Invoke(manager);

            return manager.Object;
        }

        private static OpenIddictScopeManager<OpenIddictScope> CreateScopeManager(
            Action<Mock<OpenIddictScopeManager<OpenIddictScope>>> configuration = null)
        {
            var manager = new Mock<OpenIddictScopeManager<OpenIddictScope>>(
                Mock.Of<IOpenIddictScopeStoreResolver>(),
                Mock.Of<ILogger<OpenIddictScopeManager<OpenIddictScope>>>(),
                Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>());

            configuration?.Invoke(manager);

            return manager.Object;
        }

        private static OpenIddictTokenManager<OpenIddictToken> CreateTokenManager(
            Action<Mock<OpenIddictTokenManager<OpenIddictToken>>> configuration = null)
        {
            var manager = new Mock<OpenIddictTokenManager<OpenIddictToken>>(
                Mock.Of<IOpenIddictTokenStoreResolver>(),
                Mock.Of<ILogger<OpenIddictTokenManager<OpenIddictToken>>>(),
                Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>());

            configuration?.Invoke(manager);

            return manager.Object;
        }
    }
}
