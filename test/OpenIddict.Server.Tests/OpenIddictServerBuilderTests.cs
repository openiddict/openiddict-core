/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using System.IdentityModel.Tokens.Jwt;
using System.Reflection;
using System.Threading.Tasks;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Moq;
using OpenIddict.Abstractions;
using Xunit;
using static OpenIddict.Server.OpenIddictServerEvents;

namespace OpenIddict.Server.Tests
{
    public class OpenIddictServerBuilderTests
    {
        [Fact]
        public void Constructor_ThrowsAnExceptionForNullServices()
        {
            // Arrange
            var services = (IServiceCollection) null;

            // Act and assert
            var exception = Assert.Throws<ArgumentNullException>(() => new OpenIddictServerBuilder(services));

            Assert.Equal("services", exception.ParamName);
        }

        [Fact]
        public void AddEventHandler_HandlerIsAttached()
        {
            // Arrange
            var services = CreateServices();
            var builder = CreateBuilder(services);

            // Act
            builder.AddEventHandler<ApplyAuthorizationResponse>(notification => Task.FromResult(OpenIddictServerEventState.Handled));

            // Assert
            Assert.Contains(services, service =>
                service.ServiceType == typeof(IOpenIddictServerEventHandler<ApplyAuthorizationResponse>) &&
                service.ImplementationInstance.GetType() == typeof(OpenIddictServerEventHandler<ApplyAuthorizationResponse>));
        }

        [Fact]
        public void AddEventHandler_ThrowsAnExceptionForUnsupportedLifetime()
        {
            // Arrange
            var services = CreateServices();
            var builder = CreateBuilder(services);

            // Act and assert
            var exception = Assert.Throws<ArgumentException>(delegate
            {
                return builder.AddEventHandler<CustomHandler>(ServiceLifetime.Transient);
            });

            Assert.Equal("lifetime", exception.ParamName);
            Assert.StartsWith("Handlers cannot be registered as transient services.", exception.Message);
        }

        [Fact]
        public void AddEventHandler_ThrowsAnExceptionForOpenGenericHandlerType()
        {
            // Arrange
            var services = CreateServices();
            var builder = CreateBuilder(services);

            // Act and assert
            var exception = Assert.Throws<ArgumentException>(delegate
            {
                return builder.AddEventHandler(typeof(OpenIddictServerEventHandler<>));
            });

            Assert.Equal("type", exception.ParamName);
            Assert.StartsWith("The specified type is invalid.", exception.Message);
        }

        [Fact]
        public void AddEventHandler_ThrowsAnExceptionForNonHandlerType()
        {
            // Arrange
            var services = CreateServices();
            var builder = CreateBuilder(services);

            // Act and assert
            var exception = Assert.Throws<ArgumentException>(delegate
            {
                return builder.AddEventHandler(typeof(object));
            });

            Assert.Equal("type", exception.ParamName);
            Assert.StartsWith("The specified type is invalid.", exception.Message);
        }

        [Fact]
        public void AddEventHandler_HandlerIsRegistered()
        {
            // Arrange
            var services = CreateServices();
            var builder = CreateBuilder(services);

            // Act
            builder.AddEventHandler<CustomHandler>(ServiceLifetime.Singleton);

            // Assert
            Assert.Contains(services, service =>
                service.ServiceType == typeof(IOpenIddictServerEventHandler<ApplyAuthorizationResponse>) &&
                service.ImplementationType == typeof(CustomHandler) &&
                service.Lifetime == ServiceLifetime.Singleton);
            Assert.Contains(services, service =>
                service.ServiceType == typeof(IOpenIddictServerEventHandler<HandleAuthorizationRequest>) &&
                service.ImplementationType == typeof(CustomHandler) &&
                service.Lifetime == ServiceLifetime.Singleton);
        }

        [Fact]
        public void Configure_OptionsAreCorrectlyAmended()
        {
            // Arrange
            var services = CreateServices();
            var builder = CreateBuilder(services);

            // Act
            builder.Configure(configuration => configuration.AccessTokenLifetime = TimeSpan.FromDays(1));

            var options = GetOptions(services);

            // Assert
            Assert.Equal(TimeSpan.FromDays(1), options.AccessTokenLifetime);
        }

        [Fact]
        public void AddDevelopmentSigningCertificate_ThrowsAnExceptionForNullSubject()
        {
            // Arrange
            var services = CreateServices();
            var builder = CreateBuilder(services);

            // Act and assert
            var exception = Assert.Throws<ArgumentNullException>(delegate
            {
                builder.AddDevelopmentSigningCertificate(subject: null);
            });

            Assert.Equal("subject", exception.ParamName);
        }

#if SUPPORTS_CERTIFICATE_GENERATION
        [Fact]
        public void AddDevelopmentSigningCertificate_CanGenerateCertificate()
        {
            // Arrange
            var services = CreateServices();
            var builder = CreateBuilder(services);

            // Act
            builder.AddDevelopmentSigningCertificate();

            var options = GetOptions(services);

            // Assert
            Assert.Equal(1, options.SigningCredentials.Count);
            Assert.Equal(SecurityAlgorithms.RsaSha256, options.SigningCredentials[0].Algorithm);
            Assert.NotNull(options.SigningCredentials[0].Kid);
        }
#else
        [Fact]
        public void AddDevelopmentSigningCertificate_ThrowsAnExceptionOnUnsupportedPlatforms()
        {
            // Arrange
            var services = CreateServices();
            var builder = CreateBuilder(services);

            builder.AddDevelopmentSigningCertificate();

            // Act and assert
            var exception = Assert.Throws<PlatformNotSupportedException>(delegate 
            {
                return GetOptions(services);
            });

            Assert.Equal("X.509 certificate generation is not supported on this platform.", exception.Message);
        }
#endif

        [Fact]
        public void AddEphemeralSigningKey_SigningKeyIsCorrectlyAdded()
        {
            // Arrange
            var services = CreateServices();
            var builder = CreateBuilder(services);

            // Act
            builder.AddEphemeralSigningKey();

            var options = GetOptions(services);

            // Assert
            Assert.Equal(1, options.SigningCredentials.Count);
        }

        [Theory]
        [InlineData(SecurityAlgorithms.RsaSha256)]
        [InlineData(SecurityAlgorithms.RsaSha384)]
        [InlineData(SecurityAlgorithms.RsaSha512)]
#if SUPPORTS_ECDSA
        [InlineData(SecurityAlgorithms.EcdsaSha256)]
        [InlineData(SecurityAlgorithms.EcdsaSha384)]
        [InlineData(SecurityAlgorithms.EcdsaSha512)]
#endif
        public void AddEphemeralSigningKey_SigningCredentialsUseSpecifiedAlgorithm(string algorithm)
        {
            // Arrange
            var services = CreateServices();
            var builder = CreateBuilder(services);

            // Act
            builder.AddEphemeralSigningKey(algorithm);

            var options = GetOptions(services);
            var credentials = options.SigningCredentials[0];

            // Assert
            Assert.Equal(algorithm, credentials.Algorithm);
        }

        [Fact]
        public void AddEncryptingKey_EncryptingKeyIsCorrectlyAdded()
        {
            // Arrange
            var services = CreateServices();
            var builder = CreateBuilder(services);

            var factory = Mock.Of<CryptoProviderFactory>(mock =>
                mock.IsSupportedAlgorithm(SecurityAlgorithms.Aes256KW, It.IsAny<SecurityKey>()));

            var key = Mock.Of<SecurityKey>(mock => mock.CryptoProviderFactory == factory);

            // Act
            builder.AddEncryptingKey(key);

            var options = GetOptions(services);

            // Assert
            Assert.Same(key, options.EncryptingCredentials[0].Key);
        }

        [Theory]
        [InlineData(SecurityAlgorithms.HmacSha256)]
        [InlineData(SecurityAlgorithms.RsaSha256)]
#if SUPPORTS_ECDSA
        [InlineData(SecurityAlgorithms.EcdsaSha256)]
        [InlineData(SecurityAlgorithms.EcdsaSha384)]
        [InlineData(SecurityAlgorithms.EcdsaSha512)]
#endif
        public void AddSigningKey_SigningKeyIsCorrectlyAdded(string algorithm)
        {
            // Arrange
            var services = CreateServices();
            var builder = CreateBuilder(services);

            var factory = Mock.Of<CryptoProviderFactory>(mock =>
                mock.IsSupportedAlgorithm(algorithm, It.IsAny<SecurityKey>()));

            var key = Mock.Of<SecurityKey>(mock => mock.CryptoProviderFactory == factory);

            // Act
            builder.AddSigningKey(key);

            var options = GetOptions(services);

            // Assert
            Assert.Same(key, options.SigningCredentials[0].Key);
        }

        [Fact]
        public void AddSigningCertificate_SigningKeyIsCorrectlyAdded()
        {
            // Arrange
            var services = CreateServices();
            var builder = CreateBuilder(services);

            // Act
            builder.AddSigningCertificate(
                assembly: typeof(OpenIddictServerBuilderTests).GetTypeInfo().Assembly,
                resource: "OpenIddict.Server.Tests.Certificate.pfx",
                password: "OpenIddict");

            var options = GetOptions(services);

            // Assert
            Assert.IsType<X509SecurityKey>(options.SigningCredentials[0].Key);
        }

        [Fact]
        public void AllowAuthorizationCodeFlow_CodeFlowIsAddedToGrantTypes()
        {
            // Arrange
            var services = CreateServices();
            var builder = CreateBuilder(services);

            // Act
            builder.AllowAuthorizationCodeFlow();

            var options = GetOptions(services);

            // Assert
            Assert.Contains(OpenIddictConstants.GrantTypes.AuthorizationCode, options.GrantTypes);
        }

        [Fact]
        public void AllowClientCredentialsFlow_ClientCredentialsFlowIsAddedToGrantTypes()
        {
            // Arrange
            var services = CreateServices();
            var builder = CreateBuilder(services);

            // Act
            builder.AllowClientCredentialsFlow();

            var options = GetOptions(services);

            // Assert
            Assert.Contains(OpenIddictConstants.GrantTypes.ClientCredentials, options.GrantTypes);
        }

        [Fact]
        public void AllowCustomFlow_CustomFlowIsAddedToGrantTypes()
        {
            // Arrange
            var services = CreateServices();
            var builder = CreateBuilder(services);

            // Act
            builder.AllowCustomFlow("urn:ietf:params:oauth:grant-type:custom_grant");

            var options = GetOptions(services);

            // Assert
            Assert.Contains("urn:ietf:params:oauth:grant-type:custom_grant", options.GrantTypes);
        }

        [Fact]
        public void AllowImplicitFlow_ImplicitFlowIsAddedToGrantTypes()
        {
            // Arrange
            var services = CreateServices();
            var builder = CreateBuilder(services);

            // Act
            builder.AllowImplicitFlow();

            var options = GetOptions(services);

            // Assert
            Assert.Contains(OpenIddictConstants.GrantTypes.Implicit, options.GrantTypes);
        }

        [Fact]
        public void AllowPasswordFlow_PasswordFlowIsAddedToGrantTypes()
        {
            // Arrange
            var services = CreateServices();
            var builder = CreateBuilder(services);

            // Act
            builder.AllowPasswordFlow();

            var options = GetOptions(services);

            // Assert
            Assert.Contains(OpenIddictConstants.GrantTypes.Password, options.GrantTypes);
        }

        [Fact]
        public void AllowRefreshTokenFlow_RefreshTokenFlowIsAddedToGrantTypes()
        {
            // Arrange
            var services = CreateServices();
            var builder = CreateBuilder(services);

            // Act
            builder.AllowRefreshTokenFlow();

            var options = GetOptions(services);

            // Assert
            Assert.Contains(OpenIddictConstants.GrantTypes.RefreshToken, options.GrantTypes);
        }

        [Fact]
        public void DisableAuthorizationStorage_AuthorizationStorageIsDisabled()
        {
            // Arrange
            var services = CreateServices();
            var builder = CreateBuilder(services);

            // Act
            builder.DisableAuthorizationStorage();

            var options = GetOptions(services);

            // Assert
            Assert.True(options.DisableAuthorizationStorage);
        }

        [Fact]
        public void DisableConfigurationEndpoint_ConfigurationEndpointIsDisabled()
        {
            // Arrange
            var services = CreateServices();
            var builder = CreateBuilder(services);

            // Act
            builder.DisableConfigurationEndpoint();

            var options = GetOptions(services);

            // Assert
            Assert.Equal(PathString.Empty, options.ConfigurationEndpointPath);
        }

        [Fact]
        public void DisableCryptographyEndpoint_CryptographyEndpointIsDisabled()
        {
            // Arrange
            var services = CreateServices();
            var builder = CreateBuilder(services);

            // Act
            builder.DisableCryptographyEndpoint();

            var options = GetOptions(services);

            // Assert
            Assert.Equal(PathString.Empty, options.CryptographyEndpointPath);
        }

        [Fact]
        public void DisableSlidingExpiration_SlidingExpirationIsDisabled()
        {
            // Arrange
            var services = CreateServices();
            var builder = CreateBuilder(services);

            // Act
            builder.DisableSlidingExpiration();

            var options = GetOptions(services);

            // Assert
            Assert.False(options.UseSlidingExpiration);
        }

        [Fact]
        public void DisableTokenStorage_TokenStorageIsDisabled()
        {
            // Arrange
            var services = CreateServices();
            var builder = CreateBuilder(services);

            // Act
            builder.DisableTokenStorage();

            var options = GetOptions(services);

            // Assert
            Assert.True(options.DisableTokenStorage);
        }

        [Fact]
        public void EnableAuthorizationEndpoint_AuthorizationEndpointIsEnabled()
        {
            // Arrange
            var services = CreateServices();
            var builder = CreateBuilder(services);

            // Act
            builder.EnableAuthorizationEndpoint("/endpoint-path");

            var options = GetOptions(services);

            // Assert
            Assert.Equal("/endpoint-path", options.AuthorizationEndpointPath);
        }

        [Fact]
        public void EnableIntrospectionEndpoint_IntrospectionEndpointIsEnabled()
        {
            // Arrange
            var services = CreateServices();
            var builder = CreateBuilder(services);

            // Act
            builder.EnableIntrospectionEndpoint("/endpoint-path");

            var options = GetOptions(services);

            // Assert
            Assert.Equal("/endpoint-path", options.IntrospectionEndpointPath);
        }

        [Fact]
        public void EnableLogoutEndpoint_LogoutEndpointIsEnabled()
        {
            // Arrange
            var services = CreateServices();
            var builder = CreateBuilder(services);

            // Act
            builder.EnableLogoutEndpoint("/endpoint-path");

            var options = GetOptions(services);

            // Assert
            Assert.Equal("/endpoint-path", options.LogoutEndpointPath);
        }

        [Fact]
        public void EnableRequestCaching_RequestCachingIsEnabled()
        {
            // Arrange
            var services = CreateServices();
            var builder = CreateBuilder(services);

            // Act
            builder.EnableRequestCaching();

            var options = GetOptions(services);

            // Assert
            Assert.True(options.EnableRequestCaching);
        }

        [Fact]
        public void EnableRevocationEndpoint_RevocationEndpointIsEnabled()
        {
            // Arrange
            var services = CreateServices();
            var builder = CreateBuilder(services);

            // Act
            builder.EnableRevocationEndpoint("/endpoint-path");

            var options = GetOptions(services);

            // Assert
            Assert.Equal("/endpoint-path", options.RevocationEndpointPath);
        }

        [Fact]
        public void DisableScopeValidation_ScopeValidationIsDisabled()
        {
            // Arrange
            var services = CreateServices();
            var builder = CreateBuilder(services);

            // Act
            builder.DisableScopeValidation();

            var options = GetOptions(services);

            // Assert
            Assert.True(options.DisableScopeValidation);
        }

        [Fact]
        public void EnableTokenEndpoint_TokenEndpointIsEnabled()
        {
            // Arrange
            var services = CreateServices();
            var builder = CreateBuilder(services);

            // Act
            builder.EnableTokenEndpoint("/endpoint-path");

            var options = GetOptions(services);

            // Assert
            Assert.Equal("/endpoint-path", options.TokenEndpointPath);
        }

        [Fact]
        public void EnableUserinfoEndpoint_UserinfoEndpointIsEnabled()
        {
            // Arrange
            var services = CreateServices();
            var builder = CreateBuilder(services);

            // Act
            builder.EnableUserinfoEndpoint("/endpoint-path");

            var options = GetOptions(services);

            // Assert
            Assert.Equal("/endpoint-path", options.UserinfoEndpointPath);
        }

        [Fact]
        public void AcceptAnonymousClients_ClientIdentificationIsOptional()
        {
            // Arrange
            var services = CreateServices();
            var builder = CreateBuilder(services);

            // Act
            builder.AcceptAnonymousClients();

            var options = GetOptions(services);

            // Assert
            Assert.True(options.AcceptAnonymousClients);
        }

        [Fact]
        public void SetAccessTokenLifetime_DefaultAccessTokenLifetimeIsReplaced()
        {
            // Arrange
            var services = CreateServices();
            var builder = CreateBuilder(services);

            // Act
            builder.SetAccessTokenLifetime(TimeSpan.FromMinutes(42));

            var options = GetOptions(services);

            // Assert
            Assert.Equal(TimeSpan.FromMinutes(42), options.AccessTokenLifetime);
        }

        [Fact]
        public void SetAccessTokenLifetime_AccessTokenLifetimeCanBeSetToNull()
        {
            // Arrange
            var services = CreateServices();
            var builder = CreateBuilder(services);

            // Act
            builder.SetAccessTokenLifetime(null);

            var options = GetOptions(services);

            // Assert
            Assert.Null(options.AccessTokenLifetime);
        }

        [Fact]
        public void SetAuthorizationCodeLifetime_DefaultAuthorizationCodeLifetimeIsReplaced()
        {
            // Arrange
            var services = CreateServices();
            var builder = CreateBuilder(services);

            // Act
            builder.SetAuthorizationCodeLifetime(TimeSpan.FromMinutes(42));

            var options = GetOptions(services);

            // Assert
            Assert.Equal(TimeSpan.FromMinutes(42), options.AuthorizationCodeLifetime);
        }

        [Fact]
        public void SetAuthorizationCodeLifetime_AuthorizationCodeLifetimeCanBeSetToNull()
        {
            // Arrange
            var services = CreateServices();
            var builder = CreateBuilder(services);

            // Act
            builder.SetAuthorizationCodeLifetime(null);

            var options = GetOptions(services);

            // Assert
            Assert.Null(options.AuthorizationCodeLifetime);
        }

        [Fact]
        public void SetIdentityTokenLifetime_DefaultIdentityTokenLifetimeIsReplaced()
        {
            // Arrange
            var services = CreateServices();
            var builder = CreateBuilder(services);

            // Act
            builder.SetIdentityTokenLifetime(TimeSpan.FromMinutes(42));

            var options = GetOptions(services);

            // Assert
            Assert.Equal(TimeSpan.FromMinutes(42), options.IdentityTokenLifetime);
        }

        [Fact]
        public void SetIdentityTokenLifetime_IdentityTokenLifetimeCanBeSetToNull()
        {
            // Arrange
            var services = CreateServices();
            var builder = CreateBuilder(services);

            // Act
            builder.SetIdentityTokenLifetime(null);

            var options = GetOptions(services);

            // Assert
            Assert.Null(options.IdentityTokenLifetime);
        }

        [Fact]
        public void SetRefreshTokenLifetime_DefaultRefreshTokenLifetimeIsReplaced()
        {
            // Arrange
            var services = CreateServices();
            var builder = CreateBuilder(services);

            // Act
            builder.SetRefreshTokenLifetime(TimeSpan.FromMinutes(42));

            var options = GetOptions(services);

            // Assert
            Assert.Equal(TimeSpan.FromMinutes(42), options.RefreshTokenLifetime);
        }

        [Fact]
        public void SetRefreshTokenLifetime_RefreshTokenLifetimeCanBeSetToNull()
        {
            // Arrange
            var services = CreateServices();
            var builder = CreateBuilder(services);

            // Act
            builder.SetRefreshTokenLifetime(null);

            var options = GetOptions(services);

            // Assert
            Assert.Null(options.RefreshTokenLifetime);
        }

        [Fact]
        public void SetRequestCachingPolicy_ThrowsAnExceptionForNullPolicy()
        {
            // Arrange
            var services = CreateServices();
            var builder = CreateBuilder(services);

            // Act and assert
            var exception = Assert.Throws<ArgumentNullException>(() => builder.SetRequestCachingPolicy(null));

            Assert.Equal("policy", exception.ParamName);
        }

        [Fact]
        public void SetRequestCachingPolicy_PolicyIsUpdated()
        {
            // Arrange
            var services = CreateServices();
            var builder = CreateBuilder(services);

            var policy = new DistributedCacheEntryOptions
            {
                AbsoluteExpirationRelativeToNow = TimeSpan.FromDays(42),
                SlidingExpiration = TimeSpan.FromSeconds(42)
            };

            // Act
            builder.SetRequestCachingPolicy(policy);

            var options = GetOptions(services);

            // Assert
            Assert.Same(policy, options.RequestCachingPolicy);
        }

        [Fact]
        public void SetIssuer_ThrowsAnExceptionForNullIssuer()
        {
            // Arrange
            var services = CreateServices();
            var builder = CreateBuilder(services);

            // Act and assert
            var exception = Assert.Throws<ArgumentNullException>(() => builder.SetIssuer(null));

            Assert.Equal("address", exception.ParamName);
        }

        [Fact]
        public void SetIssuer_AddressIsReplaced()
        {
            // Arrange
            var services = CreateServices();
            var builder = CreateBuilder(services);

            // Act
            builder.SetIssuer(new Uri("http://www.fabrikam.com/"));

            var options = GetOptions(services);

            // Assert
            Assert.Equal(new Uri("http://www.fabrikam.com/"), options.Issuer);
        }

        [Fact]
        public void RegisterClaims_ClaimsAreAdded()
        {
            // Arrange
            var services = CreateServices();
            var builder = CreateBuilder(services);

            // Act
            builder.RegisterClaims("custom_claim_1", "custom_claim_2");

            var options = GetOptions(services);

            // Assert
            Assert.Contains("custom_claim_1", options.Claims);
            Assert.Contains("custom_claim_2", options.Claims);
        }

        [Fact]
        public void RegisterScopes_ScopesAreAdded()
        {
            // Arrange
            var services = CreateServices();
            var builder = CreateBuilder(services);

            // Act
            builder.RegisterScopes("custom_scope_1", "custom_scope_2");

            var options = GetOptions(services);

            // Assert
            Assert.Contains("custom_scope_1", options.Scopes);
            Assert.Contains("custom_scope_2", options.Scopes);
        }

        [Fact]
        public void RequireProofKeyForCodeExchange_PkceIsEnforced()
        {
            // Arrange
            var services = CreateServices();
            var builder = CreateBuilder(services);

            // Act
            builder.RequireProofKeyForCodeExchange();

            var options = GetOptions(services);

            // Assert
            Assert.True(options.RequireProofKeyForCodeExchange);
        }

        [Fact]
        public void UseDataProtectionProvider_DefaultProviderIsReplaced()
        {
            // Arrange
            var services = CreateServices();
            var builder = CreateBuilder(services);

            // Act
            builder.UseDataProtectionProvider(new EphemeralDataProtectionProvider());

            var options = GetOptions(services);

            // Assert
            Assert.IsType<EphemeralDataProtectionProvider>(options.DataProtectionProvider);
        }

        [Fact]
        public void UseJsonWebTokens_AccessTokenHandlerIsCorrectlySet()
        {
            // Arrange
            var services = CreateServices();
            var builder = CreateBuilder(services);

            // Act
            builder.UseJsonWebTokens();

            var options = GetOptions(services);

            // Assert
            Assert.IsType<JwtSecurityTokenHandler>(options.AccessTokenHandler);
        }

        [Fact]
        public void UseReferenceTokens_ReferenceTokensAreEnabled()
        {
            // Arrange
            var services = CreateServices();
            var builder = CreateBuilder(services);

            // Act
            builder.UseReferenceTokens();

            var options = GetOptions(services);

            // Assert
            Assert.True(options.UseReferenceTokens);
        }

        private static IServiceCollection CreateServices()
            => new ServiceCollection().AddOptions();

        private static OpenIddictServerBuilder CreateBuilder(IServiceCollection services)
            => new OpenIddictServerBuilder(services);

        private static OpenIddictServerOptions GetOptions(IServiceCollection services)
        {
            var provider = services.BuildServiceProvider();
            var options = provider.GetRequiredService<IOptionsMonitor<OpenIddictServerOptions>>();
            return options.Get(OpenIddictServerDefaults.AuthenticationScheme);
        }

        public class CustomHandler : IOpenIddictServerEventHandler<ApplyAuthorizationResponse>,
                                     IOpenIddictServerEventHandler<HandleAuthorizationRequest>
        {
            public Task<OpenIddictServerEventState> HandleAsync(ApplyAuthorizationResponse notification)
            {
                throw new NotImplementedException();
            }

            public Task<OpenIddictServerEventState> HandleAsync(HandleAuthorizationRequest notification)
            {
                throw new NotImplementedException();
            }
        }
    }
}
