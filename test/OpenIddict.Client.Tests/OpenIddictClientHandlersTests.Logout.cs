/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Xunit;
using static OpenIddict.Abstractions.OpenIddictExceptions;
using static OpenIddict.Client.OpenIddictClientEvents;
using static OpenIddict.Client.OpenIddictClientHandlers.Logout;
using static OpenIddict.Client.OpenIddictClientModels;

namespace OpenIddict.Client.Tests;

public class OpenIddictClientHandlersLogoutTests
{
    private const string Issuer = "https://www.contoso.com/";

    private static readonly RsaSecurityKey ServerSigningKey = new(RSA.Create(keySizeInBits: 2048)) { KeyId = "server_key" };

    [Fact]
    public async Task AuthenticateWithLogoutTokenAsync_ValidTokenIsAccepted()
    {
        // Arrange
        using var provider = CreateProvider();
        var service = provider.GetRequiredService<OpenIddictClientService>();

        // Act
        var result = await service.AuthenticateWithLogoutTokenAsync(new() { LogoutToken = CreateToken(sub: "Bob", sid: "session") });

        // Assert
        Assert.Equal("Contoso", result.Registration.RegistrationId);
        Assert.Equal(new Uri(Issuer), result.Issuer);
        Assert.Equal("Bob", result.Subject);
        Assert.Equal("session", result.SessionId);
        Assert.Equal("session", result.LogoutTokenPrincipal.GetClaim(Claims.SessionId));
        Assert.Equal("Contoso", result.Principal.GetClaim(Claims.Private.RegistrationId));
    }

    [Theory]
    [InlineData(null)]
    [InlineData(JsonWebTokenTypes.GenericJsonWebToken)]
    [InlineData(JsonWebTokenTypes.LogoutToken)]
    [InlineData("application/logout+jwt")]
    public async Task AuthenticateWithLogoutTokenAsync_AllowedTypesAreAccepted(string? type)
    {
        // Arrange
        using var provider = CreateProvider();
        var service = provider.GetRequiredService<OpenIddictClientService>();

        // Act
        var result = await service.AuthenticateWithLogoutTokenAsync(new() { LogoutToken = CreateToken(sid: "session", type: type) });

        // Assert
        Assert.Equal("session", result.SessionId);
    }

    public static IEnumerable<object[]> InvalidTokens => new[]
    {
        "at_jwt_type", "missing_events", "invalid_events", "nonce", "no_subject_or_session", "wrong_audience",
        "wrong_issuer", "wrong_key", "unsigned", "expired", "stale_iat_without_exp", "future_iat", "missing_iat",
        "missing_jti", "malformed"
    }.Select(static scenario => new object[] { scenario });

    [Theory]
    [MemberData(nameof(InvalidTokens))]
    public async Task AuthenticateWithLogoutTokenAsync_InvalidTokensAreRejected(string scenario)
    {
        // Arrange
        using var provider = CreateProvider();
        var service = provider.GetRequiredService<OpenIddictClientService>();

        var (token, description) = scenario switch
        {
            "at_jwt_type"            => (CreateToken(sid: "session", type: JsonWebTokenTypes.AccessToken), SR.GetResourceString(SR.ID2089)),
            "missing_events"         => (CreateToken(sid: "session", events: null), SR.FormatID2382(Claims.Events)),
            "invalid_events"         => (CreateToken(sid: "session", events: """{"http://schemas.openid.net/event/backchannel-logout":true}"""), SR.FormatID2382(Claims.Events)),
            "nonce"                  => (CreateToken(sid: "session", nonce: "nonce"), SR.GetResourceString(SR.ID2383)),
            "no_subject_or_session"  => (CreateToken(), SR.FormatID2382(Claims.SessionId)),
            "wrong_audience"         => (CreateToken(sid: "session", audience: "Other"), SR.GetResourceString(SR.ID2381)),
            "wrong_issuer"           => (CreateToken(sid: "session", issuer: "https://www.fabrikam.com/"), SR.GetResourceString(SR.ID2381)),
            "wrong_key"              => (CreateToken(sid: "session", key: new RsaSecurityKey(RSA.Create(2048)) { KeyId = "server_key" }), SR.GetResourceString(SR.ID2091)),
            "unsigned"               => (CreateToken(sid: "session", unsigned: true), null),
            "expired"                => (CreateToken(sid: "session", expiration: DateTimeOffset.UtcNow.AddMinutes(-10)), SR.GetResourceString(SR.ID2385)),
            "stale_iat_without_exp"  => (CreateToken(sid: "session", expires: false, issuedAt: DateTimeOffset.UtcNow.AddHours(-1)), SR.GetResourceString(SR.ID2385)),
            "future_iat"             => (CreateToken(sid: "session", expires: false, issuedAt: DateTimeOffset.UtcNow.AddHours(1)), SR.GetResourceString(SR.ID2385)),
            "missing_iat"            => (CreateToken(sid: "session", issuedAt: DateTimeOffset.MinValue), SR.FormatID2382(Claims.IssuedAt)),
            "missing_jti"            => (CreateToken(sid: "session", identifier: string.Empty), SR.FormatID2382(Claims.JwtId)),
            "malformed"              => ("eyJhbGciOiJub25lIn0.invalid.", SR.GetResourceString(SR.ID2380)),

            _ => throw new InvalidOperationException()
        };

        // Act and assert
        var exception = await Assert.ThrowsAsync<ProtocolException>(
            async () => await service.AuthenticateWithLogoutTokenAsync(new() { LogoutToken = token }));

        Assert.NotNull(exception.Error);

        if (description is not null)
        {
            Assert.Equal(description, exception.ErrorDescription);
        }
    }

    [Fact]
    public async Task AuthenticateWithLogoutTokenAsync_ReplayedTokenIsRejected()
    {
        // Arrange
        using var provider = CreateProvider();
        var service = provider.GetRequiredService<OpenIddictClientService>();
        var token = CreateToken(sid: "session", expires: false);

        // Act
        await service.AuthenticateWithLogoutTokenAsync(new() { LogoutToken = token });
        var exception = await Assert.ThrowsAsync<ProtocolException>(
            async () => await service.AuthenticateWithLogoutTokenAsync(new() { LogoutToken = token }));

        // Assert
        Assert.Equal(SR.GetResourceString(SR.ID2386), exception.ErrorDescription);
    }

    [Fact]
    public async Task AuthenticateWithLogoutTokenAsync_DistributedCacheIsUsedForReplayProtection()
    {
        // Arrange
        var cache = new TestDistributedCache();
        using var provider = CreateProvider(services => services.AddSingleton<IDistributedCache>(cache));
        var service = provider.GetRequiredService<OpenIddictClientService>();
        var token = CreateToken(sid: "session", identifier: "identifier");

        // Act
        await service.AuthenticateWithLogoutTokenAsync(new() { LogoutToken = token });
        var exception = await Assert.ThrowsAsync<ProtocolException>(
            async () => await service.AuthenticateWithLogoutTokenAsync(new() { LogoutToken = token }));

        // Assert
        Assert.Equal(SR.GetResourceString(SR.ID2386), exception.ErrorDescription);
        Assert.Contains(cache.Entries.Keys, key => key.EndsWith(" identifier", StringComparison.Ordinal));
    }

    [Fact]
    public async Task AuthenticateWithLogoutTokenAsync_TokenWithoutSessionIsRejectedWhenSessionIsRequired()
    {
        // Arrange
        using var provider = CreateProvider(configuration: registration => registration.BackchannelLogoutSessionRequired = true);
        var service = provider.GetRequiredService<OpenIddictClientService>();

        // Act
        var exception = await Assert.ThrowsAsync<ProtocolException>(
            async () => await service.AuthenticateWithLogoutTokenAsync(new() { LogoutToken = CreateToken(sub: "Bob") }));

        // Assert
        Assert.Equal(SR.FormatID2382(Claims.SessionId), exception.ErrorDescription);
    }

    [Fact]
    public async Task AuthenticateWithLogoutTokenAsync_RegistrationIsSelectedUsingAudience()
    {
        // Arrange
        using var provider = CreateProvider(services => services.AddOpenIddict().AddClient().AddRegistration(new OpenIddictClientRegistration
        {
            ClientId = "Other",
            Configuration = CreateConfiguration(),
            Issuer = new Uri(Issuer, UriKind.Absolute),
            RegistrationId = "Other"
        }));

        var service = provider.GetRequiredService<OpenIddictClientService>();

        // Act
        var result = await service.AuthenticateWithLogoutTokenAsync(new() { LogoutToken = CreateToken(sid: "session", audience: "Other") });

        // Assert
        Assert.Equal("Other", result.Registration.RegistrationId);
    }

    [Fact]
    public async Task AuthenticateWithLogoutTokenAsync_ExplicitRegistrationMustMatchIssuer()
    {
        // Arrange
        using var provider = CreateProvider(services => services.AddOpenIddict().AddClient().AddRegistration(new OpenIddictClientRegistration
        {
            ClientId = "Fabrikam",
            Configuration = new OpenIddictConfiguration { Issuer = new Uri("https://www.fabrikam.com/", UriKind.Absolute) },
            Issuer = new Uri("https://www.fabrikam.com/", UriKind.Absolute),
            RegistrationId = "Fabrikam"
        }));

        var service = provider.GetRequiredService<OpenIddictClientService>();

        // Act
        var exception = await Assert.ThrowsAsync<ProtocolException>(async () => await service.AuthenticateWithLogoutTokenAsync(new()
        {
            LogoutToken = CreateToken(sid: "session"),
            RegistrationId = "Fabrikam"
        }));

        // Assert
        Assert.Equal(SR.GetResourceString(SR.ID2381), exception.ErrorDescription);
    }

    [Fact]
    public async Task AuthenticateWithLogoutTokenAsync_MaximumAgeIsUsedForTokensWithoutExpiration()
    {
        // Arrange
        using var provider = CreateProvider(services => services.AddOpenIddict().AddClient()
            .SetLogoutTokenMaximumAge(TimeSpan.FromHours(2)));

        var service = provider.GetRequiredService<OpenIddictClientService>();

        // Act
        var result = await service.AuthenticateWithLogoutTokenAsync(new()
        {
            LogoutToken = CreateToken(sid: "session", expires: false, issuedAt: DateTimeOffset.UtcNow.AddHours(-1))
        });

        // Assert
        Assert.Equal("session", result.SessionId);
    }

    [Fact]
    public async Task ExtractLogoutMetadata_MetadataIsExtracted()
    {
        // Arrange
        using var provider = CreateProvider();
        var context = CreateConfigurationContext(provider, new OpenIddictResponse
        {
            [Metadata.BackchannelLogoutSupported] = true,
            [Metadata.BackchannelLogoutSessionSupported] = false,
            [Metadata.FrontchannelLogoutSupported] = true,
            [Metadata.FrontchannelLogoutSessionSupported] = true,
            [Metadata.CheckSessionIframe] = "https://www.contoso.com/connect/checksession"
        });

        // Act
        await new ExtractLogoutMetadata().HandleAsync(context);

        // Assert
        Assert.False(context.IsRejected);
        Assert.True(context.Configuration.BackchannelLogoutSupported);
        Assert.False(context.Configuration.BackchannelLogoutSessionSupported);
        Assert.True(context.Configuration.FrontchannelLogoutSupported);
        Assert.True(context.Configuration.FrontchannelLogoutSessionSupported);
        Assert.Equal(new Uri("https://www.contoso.com/connect/checksession"), context.Configuration.CheckSessionIframe);
    }

    [Theory]
    [InlineData(Metadata.BackchannelLogoutSupported, "true", SR.ID2107)]
    [InlineData(Metadata.CheckSessionIframe, "relative/uri", SR.ID2100)]
    [InlineData(Metadata.CheckSessionIframe, 42, SR.ID2100)]
    public async Task ExtractLogoutMetadata_InvalidMetadataIsRejected(string name, object value, string identifier)
    {
        // Arrange
        using var provider = CreateProvider();
        var context = CreateConfigurationContext(provider, new OpenIddictResponse
        {
            [name] = value switch
            {
                string text => new OpenIddictParameter(text),
                int number  => new OpenIddictParameter(number),
                _ => throw new InvalidOperationException()
            }
        });

        // Act
        await new ExtractLogoutMetadata().HandleAsync(context);

        // Assert
        Assert.True(context.IsRejected);
        Assert.Equal(SR.FormatID8000(identifier), context.ErrorUri);
    }

    [Fact]
    public async Task ExtractLogoutMetadata_MissingMetadataIsIgnored()
    {
        // Arrange
        using var provider = CreateProvider();
        var context = CreateConfigurationContext(provider, new OpenIddictResponse());

        // Act
        await new ExtractLogoutMetadata().HandleAsync(context);

        // Assert
        Assert.False(context.IsRejected);
        Assert.Null(context.Configuration.BackchannelLogoutSupported);
        Assert.Null(context.Configuration.CheckSessionIframe);
    }

    [Theory]
    [InlineData(OpenIddictClientEndpointType.Redirection, "state", "state")]
    [InlineData(OpenIddictClientEndpointType.Redirection, null, null)]
    public async Task ResolveSessionState_SessionStateIsResolvedFromAuthorizationResponse(
        OpenIddictClientEndpointType type, string? value, string? expected)
    {
        // Arrange
        using var provider = CreateProvider();
        var options = provider.GetRequiredService<IOptionsMonitor<OpenIddictClientOptions>>().CurrentValue;

        var context = new ProcessAuthenticationContext(new OpenIddictClientTransaction
        {
            CancellationToken = CancellationToken.None,
            EndpointType = type,
            Options = options,
            ServiceProvider = provider
        })
        {
            Request = new OpenIddictRequest { [Parameters.SessionState] = value }
        };

        // Act
        await new ResolveSessionState().HandleAsync(context);

        // Assert
        Assert.Equal(expected, context.SessionState);
    }

    [Fact]
    public void Configuration_RegistrationLogoutUrisAreAddedToEndpointUris()
    {
        // Arrange
        using var provider = CreateProvider(configuration: registration =>
        {
            registration.BackchannelLogoutUri = new Uri("https://www.fabrikam.com/backchannel-logout", UriKind.Absolute);
            registration.FrontchannelLogoutUri = new Uri("https://www.fabrikam.com/frontchannel-logout", UriKind.Absolute);
        });

        // Act
        var options = provider.GetRequiredService<IOptionsMonitor<OpenIddictClientOptions>>().CurrentValue;

        // Assert
        Assert.Contains(new Uri("https://www.fabrikam.com/backchannel-logout", UriKind.Absolute), options.BackchannelLogoutEndpointUris);
        Assert.Contains(new Uri("https://www.fabrikam.com/frontchannel-logout", UriKind.Absolute), options.FrontchannelLogoutEndpointUris);
    }

    [Fact]
    public async Task RemoveBackchannelLogoutSessions_ThrowsWhenNoSessionStoreIsRegistered()
    {
        // Arrange
        using var provider = CreateProvider();
        var context = CreateBackchannelHandleContext(provider);

        // Act and assert
        var exception = await Assert.ThrowsAsync<InvalidOperationException>(
            async () => await new RemoveBackchannelLogoutSessions().HandleAsync(context));

        Assert.Equal(SR.GetResourceString(SR.ID0760), exception.Message);
    }

    [Fact]
    public async Task RemoveBackchannelLogoutSessions_SessionStoresAreInvoked()
    {
        // Arrange
        var store = new TestSessionStore();
        using var provider = CreateProvider(services => services.AddOpenIddict().AddClient().AddSessionStore(store));
        var context = CreateBackchannelHandleContext(provider);

        // Act
        await new RemoveBackchannelLogoutSessions().HandleAsync(context);

        // Assert
        var call = Assert.Single(store.Calls);
        Assert.Equal(("Contoso", "Bob", "session"), call);
    }

    [Theory]
    [InlineData("session", "Contoso", "https://www.contoso.com/", true)]
    [InlineData("session", null, null, true)]
    [InlineData("other", "Contoso", "https://www.contoso.com/", false)]
    [InlineData("session", "Other", "https://www.contoso.com/", false)]
    [InlineData("session", "Contoso", "https://www.fabrikam.com/", false)]
    [InlineData(null, "Contoso", "https://www.contoso.com/", false)]
    public void IsMatchingSession_ReturnsExpectedResult(string? sid, string? registration, string? issuer, bool expected)
    {
        // Arrange
        using var provider = CreateProvider();
        var options = provider.GetRequiredService<IOptionsMonitor<OpenIddictClientOptions>>().CurrentValue;

        var context = new HandleFrontchannelLogoutRequestContext(new OpenIddictClientTransaction
        {
            CancellationToken = CancellationToken.None,
            EndpointType = OpenIddictClientEndpointType.FrontchannelLogout,
            Options = options,
            Registration = options.Registrations[0],
            Request = new OpenIddictRequest(),
            ServiceProvider = provider
        })
        {
            SessionId = "session"
        };

        var identity = new System.Security.Claims.ClaimsIdentity("Cookies");

        if (sid is not null)
        {
            identity.AddClaim(new System.Security.Claims.Claim(Claims.SessionId, sid,
                System.Security.Claims.ClaimValueTypes.String, issuer ?? System.Security.Claims.ClaimsIdentity.DefaultIssuer));
        }

        if (registration is not null)
        {
            identity.AddClaim(new System.Security.Claims.Claim(Claims.Private.RegistrationId, registration));
        }

        // Act and assert
        Assert.Equal(expected, context.IsMatchingSession(new System.Security.Claims.ClaimsPrincipal(identity)));
    }

    private static HandleBackchannelLogoutRequestContext CreateBackchannelHandleContext(ServiceProvider provider)
    {
        var options = provider.GetRequiredService<IOptionsMonitor<OpenIddictClientOptions>>().CurrentValue;

        return new HandleBackchannelLogoutRequestContext(new OpenIddictClientTransaction
        {
            CancellationToken = CancellationToken.None,
            EndpointType = OpenIddictClientEndpointType.BackchannelLogout,
            Options = options,
            Registration = options.Registrations[0],
            Request = new OpenIddictRequest(),
            ServiceProvider = provider
        })
        {
            SessionId = "session",
            Subject = "Bob"
        };
    }

    private static HandleConfigurationResponseContext CreateConfigurationContext(ServiceProvider provider, OpenIddictResponse response)
    {
        var options = provider.GetRequiredService<IOptionsMonitor<OpenIddictClientOptions>>().CurrentValue;

        return new HandleConfigurationResponseContext(new OpenIddictClientTransaction
        {
            CancellationToken = CancellationToken.None,
            Options = options,
            Registration = options.Registrations[0],
            ServiceProvider = provider
        })
        {
            Configuration = new OpenIddictConfiguration(),
            RemoteUri = new Uri("https://www.contoso.com/.well-known/openid-configuration"),
            Request = new OpenIddictRequest(),
            Response = response
        };
    }

    private static string CreateToken(
        string? sub = null,
        string? sid = null,
        string? type = JsonWebTokenTypes.LogoutToken,
        string issuer = Issuer,
        string audience = "Fabrikam",
        string? events = """{"http://schemas.openid.net/event/backchannel-logout":{}}""",
        string? nonce = null,
        SecurityKey? key = null,
        bool unsigned = false,
        bool expires = true,
        DateTimeOffset? expiration = null,
        DateTimeOffset? issuedAt = null,
        string? identifier = null)
    {
        var claims = new Dictionary<string, object>(StringComparer.Ordinal)
        {
            [Claims.Audience] = audience,
            [Claims.Issuer] = issuer
        };

        if (issuedAt != DateTimeOffset.MinValue)
        {
            claims[Claims.IssuedAt] = (issuedAt ?? DateTimeOffset.UtcNow).ToUnixTimeSeconds();
        }

        if (identifier is null)
        {
            claims[Claims.JwtId] = Guid.NewGuid().ToString();
        }

        else if (identifier.Length is not 0)
        {
            claims[Claims.JwtId] = identifier;
        }

        if (expires)
        {
            claims[Claims.ExpiresAt] = (expiration ?? DateTimeOffset.UtcNow.AddMinutes(2)).ToUnixTimeSeconds();
        }

        if (events is not null)
        {
            claims[Claims.Events] = JsonDocument.Parse(events).RootElement.Clone();
        }

        if (sub is not null)
        {
            claims[Claims.Subject] = sub;
        }

        if (sid is not null)
        {
            claims[Claims.SessionId] = sid;
        }

        if (nonce is not null)
        {
            claims[Claims.Nonce] = nonce;
        }

        var handler = new JsonWebTokenHandler { SetDefaultTimesOnTokenCreation = false };
        var descriptor = new SecurityTokenDescriptor
        {
            Claims = claims,
            SigningCredentials = unsigned ? null : new SigningCredentials(key ?? ServerSigningKey, SecurityAlgorithms.RsaSha256)
        };

        if (type is not null)
        {
            descriptor.TokenType = type;
        }

        var token = handler.CreateToken(descriptor);
        if (type is not null)
        {
            return token;
        }

        // Note: IdentityModel always adds a "typ" header: remove it to create a token without explicit type.
        var parts = token.Split('.');
        var header = JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(Base64UrlEncoder.Decode(parts[0]))!;
        header.Remove(JwtHeaderParameterNames.Typ);

        var encoded = Base64UrlEncoder.Encode(JsonSerializer.Serialize(header));
        var input = encoded + "." + parts[1];

        var signature = ServerSigningKey.Rsa.SignData(System.Text.Encoding.ASCII.GetBytes(input), HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

        return input + "." + Base64UrlEncoder.Encode(signature);
    }

    private static OpenIddictConfiguration CreateConfiguration()
    {
        var configuration = new OpenIddictConfiguration { Issuer = new Uri(Issuer, UriKind.Absolute) };
        configuration.SigningKeys.Add(ServerSigningKey);

        return configuration;
    }

    private static ServiceProvider CreateProvider(
        Action<IServiceCollection>? services = null,
        Action<OpenIddictClientRegistration>? configuration = null)
    {
        var collection = new ServiceCollection();

        collection.AddOpenIddict()
            .AddClient(options =>
            {
                options.AllowClientCredentialsFlow();

                options.AddEphemeralEncryptionKey()
                       .AddEphemeralSigningKey();

                var registration = new OpenIddictClientRegistration
                {
                    ClientId = "Fabrikam",
                    Configuration = CreateConfiguration(),
                    Issuer = new Uri(Issuer, UriKind.Absolute),
                    RegistrationId = "Contoso"
                };

                configuration?.Invoke(registration);

                options.AddRegistration(registration);
            });

        services?.Invoke(collection);

        return collection.BuildServiceProvider();
    }

    private sealed class TestSessionStore : IOpenIddictClientSessionStore
    {
        public List<(string?, string?, string?)> Calls { get; } = [];

        public ValueTask<long> RemoveSessionsAsync(OpenIddictClientRegistration registration,
            string? subject, string? sessionId, CancellationToken cancellationToken)
        {
            Calls.Add((registration.RegistrationId, subject, sessionId));

            return new(1);
        }
    }

    private sealed class TestDistributedCache : IDistributedCache
    {
        public ConcurrentDictionary<string, byte[]> Entries { get; } = new(StringComparer.Ordinal);

        public byte[]? Get(string key) => Entries.TryGetValue(key, out var value) ? value : null;

        public Task<byte[]?> GetAsync(string key, CancellationToken token = default) => Task.FromResult(Get(key));

        public void Refresh(string key)
        {
        }

        public Task RefreshAsync(string key, CancellationToken token = default) => Task.CompletedTask;

        public void Remove(string key) => Entries.TryRemove(key, out _);

        public Task RemoveAsync(string key, CancellationToken token = default)
        {
            Remove(key);
            return Task.CompletedTask;
        }

        public void Set(string key, byte[] value, DistributedCacheEntryOptions options) => Entries[key] = value;

        public Task SetAsync(string key, byte[] value, DistributedCacheEntryOptions options, CancellationToken token = default)
        {
            Set(key, value, options);
            return Task.CompletedTask;
        }
    }
}
