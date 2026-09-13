using System.Collections.Immutable;
using System.Security.Claims;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Xunit;
using static OpenIddict.Client.OpenIddictClientEvents;
using static OpenIddict.Client.OpenIddictClientHandlers;

namespace OpenIddict.Client.Tests;

public class OpenIddictClientRegistrationProviderTests
{
    private static readonly Uri StaticIssuer = new("https://static.contoso.com/", UriKind.Absolute);
    private static readonly Uri DynamicIssuer = new("https://tenant1.fabrikam.com/", UriKind.Absolute);

    [Fact]
    public void AddClient_RegistersStaticRegistrationProvider()
    {
        // Arrange
        using var provider = CreateProvider(registrationProvider: null);

        // Act
        var providers = provider.GetServices<IOpenIddictClientRegistrationProvider>().ToList();

        // Assert
        Assert.IsType<OpenIddictClientRegistrationProvider>(Assert.Single(providers));
    }

    [Fact]
    public async Task GetClientRegistrationByIdAsync_ResolvesAndInitializesDynamicRegistration()
    {
        // Arrange
        var source = new TestRegistrationProvider(() => CreateDynamicRegistration());
        using var provider = CreateProvider(source);
        var service = provider.GetRequiredService<OpenIddictClientService>();

        // Act
        var registration = await service.GetClientRegistrationByIdAsync("tenant1");

        // Assert
        Assert.Equal("tenant1", registration.RegistrationId);
        Assert.Equal(ClientTypes.Public, registration.ClientType);
        Assert.NotNull(registration.ConfigurationManager);
        Assert.Equal(DynamicIssuer, (await registration.ConfigurationManager.GetConfigurationAsync(default)).Issuer);
    }

    [Fact]
    public async Task GetClientRegistrationByIdAsync_ComputesDefaultIdentifierForDynamicRegistrations()
    {
        // Arrange
        var source = new TestRegistrationProvider(() => CreateDynamicRegistration(identifier: null));
        using var provider = CreateProvider(source);
        var service = provider.GetRequiredService<OpenIddictClientService>();

        var identifier = (await service.GetClientRegistrationByIssuerAsync(DynamicIssuer)).RegistrationId;

        // Act
        var registration = await service.GetClientRegistrationByIdAsync(identifier!);

        // Assert
        Assert.False(string.IsNullOrEmpty(identifier));
        Assert.Equal(identifier, registration.RegistrationId);
    }

    [Fact]
    public async Task GetClientRegistrationByIdAsync_CachesDynamicRegistrations()
    {
        // Arrange
        var source = new TestRegistrationProvider(() => CreateDynamicRegistration());
        using var provider = CreateProvider(source);
        var service = provider.GetRequiredService<OpenIddictClientService>();

        // Act
        var first = await service.GetClientRegistrationByIdAsync("tenant1");
        var second = await service.GetClientRegistrationByIdAsync("tenant1");
        var third = await service.GetClientRegistrationByProviderNameAsync("Tenant1");

        // Assert
        Assert.Same(first, second);
        Assert.Same(first, third);
        Assert.Same(first.ConfigurationManager, third.ConfigurationManager);
        Assert.Equal(1, source.FindByIdCalls);
    }

    [Fact]
    public async Task GetClientRegistrationByIdAsync_DoesNotCacheDynamicRegistrationsWhenCachingIsDisabled()
    {
        // Arrange
        var source = new TestRegistrationProvider(() => CreateDynamicRegistration());
        using var provider = CreateProvider(source, options => options.SetDynamicRegistrationCacheLifetime(null));
        var service = provider.GetRequiredService<OpenIddictClientService>();

        // Act
        var first = await service.GetClientRegistrationByIdAsync("tenant1");
        var second = await service.GetClientRegistrationByIdAsync("tenant1");

        // Assert
        Assert.NotSame(first, second);
        Assert.Equal(2, source.FindByIdCalls);
    }

    [Fact]
    public async Task GetClientRegistrationByIdAsync_RefreshesExpiredDynamicRegistrations()
    {
        // Arrange
        var clock = new MutableTimeProvider(DateTimeOffset.UtcNow);
        var source = new TestRegistrationProvider(() => CreateDynamicRegistration());
        using var provider = CreateProvider(source, options =>
        {
            options.Configure(settings => settings.TimeProvider = clock);
            options.SetDynamicRegistrationCacheLifetime(TimeSpan.FromMinutes(5));
        });

        var service = provider.GetRequiredService<OpenIddictClientService>();

        // Act
        var first = await service.GetClientRegistrationByIdAsync("tenant1");
        clock.Now += TimeSpan.FromMinutes(6);
        var second = await service.GetClientRegistrationByIdAsync("tenant1");

        // Assert
        Assert.NotSame(first, second);
        Assert.Equal(2, source.FindByIdCalls);
    }

    [Fact]
    public async Task GetClientRegistrationByIssuerAsync_DoesNotReturnStaleCachedRegistrationWhenIssuerChanged()
    {
        // Arrange
        var issuer = DynamicIssuer;
        var source = new TestRegistrationProvider(() =>
        {
            var registration = CreateDynamicRegistration();
            registration.Issuer = issuer;
            registration.Configuration!.Issuer = issuer;
            return registration;
        });

        using var provider = CreateProvider(source);
        var service = provider.GetRequiredService<OpenIddictClientService>();

        var first = await service.GetClientRegistrationByIdAsync("tenant1");
        issuer = new Uri("https://tenant1.northwind.com/", UriKind.Absolute);

        // Act
        var second = await service.GetClientRegistrationByIssuerAsync(issuer);
        var third = await service.GetClientRegistrationByIdAsync("tenant1");

        // Assert
        Assert.NotSame(first, second);
        Assert.Equal(issuer, second.Issuer);
        Assert.Equal(issuer, (await second.ConfigurationManager!.GetConfigurationAsync(default)).Issuer);
        Assert.Same(second, third);
    }

    [Fact]
    public async Task GetClientRegistrationByIssuerAsync_ReturnsCachedRegistrationWhenUnchanged()
    {
        // Arrange
        var source = new TestRegistrationProvider(() => CreateDynamicRegistration(identifier: null));
        using var provider = CreateProvider(source);
        var service = provider.GetRequiredService<OpenIddictClientService>();

        // Act
        var first = await service.GetClientRegistrationByIssuerAsync(DynamicIssuer);
        var second = await service.GetClientRegistrationByIssuerAsync(DynamicIssuer);

        // Assert
        Assert.Same(first, second);
        Assert.Same(first.ConfigurationManager, second.ConfigurationManager);
    }

    [Fact]
    public async Task GetClientRegistrationByIdAsync_ThrowsAnExceptionForUnknownIdentifier()
    {
        // Arrange
        using var provider = CreateProvider(new TestRegistrationProvider(() => CreateDynamicRegistration()));
        var service = provider.GetRequiredService<OpenIddictClientService>();

        // Act and assert
        var exception = await Assert.ThrowsAsync<InvalidOperationException>(
            async () => await service.GetClientRegistrationByIdAsync("unknown"));

        Assert.Equal(SR.GetResourceString(SR.ID0410), exception.Message);
    }

    [Fact]
    public async Task GetClientRegistrationByIdAsync_ThrowsAnExceptionForMismatchingIdentifier()
    {
        // Arrange
        var source = new TestRegistrationProvider(() => CreateDynamicRegistration(identifier: "other"), matchIdentifier: false);
        using var provider = CreateProvider(source);
        var service = provider.GetRequiredService<OpenIddictClientService>();

        // Act and assert
        var exception = await Assert.ThrowsAsync<InvalidOperationException>(
            async () => await service.GetClientRegistrationByIdAsync("tenant1"));

        Assert.Equal(SR.GetResourceString(SR.ID0558), exception.Message);
    }

    [Fact]
    public async Task GetClientRegistrationByIdAsync_RejectsUndeclaredRedirectUri()
    {
        // Arrange
        var source = new TestRegistrationProvider(() => CreateDynamicRegistration(
            redirectUri: new Uri("https://localhost/callback/unknown", UriKind.Absolute)));

        using var provider = CreateProvider(source);
        var service = provider.GetRequiredService<OpenIddictClientService>();

        // Act and assert
        var exception = await Assert.ThrowsAsync<InvalidOperationException>(
            async () => await service.GetClientRegistrationByIdAsync("tenant1"));

        Assert.StartsWith(SR.FormatID0554(Environment.NewLine, string.Empty), exception.Message, StringComparison.Ordinal);
        Assert.Contains(SR.GetResourceString(SR.ID0555), exception.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task GetClientRegistrationByIdAsync_RejectsUndeclaredPostLogoutRedirectUri()
    {
        // Arrange
        var source = new TestRegistrationProvider(() =>
        {
            var registration = CreateDynamicRegistration();
            registration.PostLogoutRedirectUri = new Uri("https://localhost/logout/unknown", UriKind.Absolute);
            return registration;
        });

        using var provider = CreateProvider(source);
        var service = provider.GetRequiredService<OpenIddictClientService>();

        // Act and assert
        var exception = await Assert.ThrowsAsync<InvalidOperationException>(
            async () => await service.GetClientRegistrationByIdAsync("tenant1"));

        Assert.Contains(SR.GetResourceString(SR.ID0556), exception.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task GetClientRegistrationByIssuerAsync_RejectsInvalidDynamicRegistration()
    {
        // Arrange
        var source = new TestRegistrationProvider(() =>
        {
            var registration = CreateDynamicRegistration();
            registration.Configuration!.Issuer = new Uri("https://attacker.com/", UriKind.Absolute);
            return registration;
        });

        using var provider = CreateProvider(source);
        var service = provider.GetRequiredService<OpenIddictClientService>();

        // Act and assert
        var exception = await Assert.ThrowsAsync<InvalidOperationException>(
            async () => await service.GetClientRegistrationByIssuerAsync(DynamicIssuer));

        Assert.Contains(SR.GetResourceString(SR.ID0395), exception.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task GetClientRegistrationByProviderNameAsync_RejectsStaticIdentifierCollision()
    {
        // Arrange
        var source = new TestRegistrationProvider(() => CreateDynamicRegistration(identifier: "STATIC"));
        using var provider = CreateProvider(source, options => options.AddRegistration(CreateStaticRegistration()));
        var service = provider.GetRequiredService<OpenIddictClientService>();

        // Act and assert
        var exception = await Assert.ThrowsAsync<InvalidOperationException>(
            async () => await service.GetClientRegistrationByProviderNameAsync("Tenant1"));

        Assert.Contains(SR.GetResourceString(SR.ID0557), exception.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task GetClientRegistrationByIdAsync_AcceptsDeclaredRedirectUri()
    {
        // Arrange
        var source = new TestRegistrationProvider(() => CreateDynamicRegistration(
            redirectUri: new Uri("https://localhost/callback", UriKind.Absolute)));

        using var provider = CreateProvider(source);
        var service = provider.GetRequiredService<OpenIddictClientService>();

        // Act
        var registration = await service.GetClientRegistrationByIdAsync("tenant1");

        // Assert
        Assert.Equal(new Uri("https://localhost/callback", UriKind.Absolute), registration.RedirectUri);
    }

    [Fact]
    public async Task GetClientRegistrationByIdAsync_PrefersStaticRegistrations()
    {
        // Arrange
        var source = new TestRegistrationProvider(() => CreateDynamicRegistration());
        using var provider = CreateProvider(source, options => options.AddRegistration(CreateStaticRegistration()));
        var service = provider.GetRequiredService<OpenIddictClientService>();
        var options = provider.GetRequiredService<IOptionsMonitor<OpenIddictClientOptions>>().CurrentValue;

        // Act
        var registration = await service.GetClientRegistrationByIdAsync("static");

        // Assert
        Assert.Same(options.Registrations[0], registration);
        Assert.Equal(0, source.FindByIdCalls);
    }

    [Fact]
    public async Task GetClientRegistrationsAsync_ReturnsStaticAndDynamicRegistrations()
    {
        // Arrange
        var source = new TestRegistrationProvider(() => CreateDynamicRegistration());
        using var provider = CreateProvider(source, options => options.AddRegistration(CreateStaticRegistration()));
        var service = provider.GetRequiredService<OpenIddictClientService>();

        // Act
        var registrations = await service.GetClientRegistrationsAsync();

        // Assert
        Assert.Collection(registrations,
            registration => Assert.Equal("static", registration.RegistrationId),
            registration => Assert.Equal("tenant1", registration.RegistrationId));
    }

    [Fact]
    public async Task GetClientRegistrationByProviderNameAsync_ThrowsAnExceptionWhenStaticAndDynamicRegistrationsShareTheName()
    {
        // Arrange
        var source = new TestRegistrationProvider(() => CreateDynamicRegistration(providerName: "Static"));
        using var provider = CreateProvider(source, options => options.AddRegistration(CreateStaticRegistration()));
        var service = provider.GetRequiredService<OpenIddictClientService>();

        // Act and assert
        var exception = await Assert.ThrowsAsync<InvalidOperationException>(
            async () => await service.GetClientRegistrationByProviderNameAsync("Static"));

        Assert.Equal(SR.GetResourceString(SR.ID0409), exception.Message);
    }

    [Fact]
    public async Task ResolveClientRegistrationFromChallengeContext_UsesUniqueDynamicRegistration()
    {
        // Arrange
        using var provider = CreateProvider(new TestRegistrationProvider(() => CreateDynamicRegistration()));
        var context = new ProcessChallengeContext(CreateTransaction(provider))
        {
            Principal = new ClaimsPrincipal(new ClaimsIdentity()),
            Request = new OpenIddictRequest()
        };

        // Act
        await new ResolveClientRegistrationFromChallengeContext(provider.GetRequiredService<OpenIddictClientService>())
            .HandleAsync(context);

        // Assert
        Assert.Equal("tenant1", context.Registration.RegistrationId);
        Assert.Equal(DynamicIssuer, context.Configuration.Issuer);
    }

    [Fact]
    public async Task ResolveClientRegistrationFromChallengeContext_ThrowsAnExceptionWhenNoRegistrationIsAvailable()
    {
        // Arrange
        using var provider = CreateProvider(registrationProvider: null);
        var context = new ProcessChallengeContext(CreateTransaction(provider))
        {
            Principal = new ClaimsPrincipal(new ClaimsIdentity()),
            Request = new OpenIddictRequest()
        };

        // Act and assert
        var exception = await Assert.ThrowsAsync<InvalidOperationException>(async () =>
            await new ResolveClientRegistrationFromChallengeContext(provider.GetRequiredService<OpenIddictClientService>())
                .HandleAsync(context));

        Assert.Equal(SR.GetResourceString(SR.ID0304), exception.Message);
    }

    [Fact]
    public async Task ResolveClientRegistrationFromStateToken_ResolvesDynamicRegistration()
    {
        // Arrange
        using var provider = CreateProvider(new TestRegistrationProvider(() => CreateDynamicRegistration()));
        var context = new ProcessAuthenticationContext(CreateTransaction(provider))
        {
            StateTokenPrincipal = new ClaimsPrincipal(new ClaimsIdentity("Bearer")
                .SetClaim(Claims.Private.RegistrationId, "tenant1"))
        };

        // Act
        await new ResolveClientRegistrationFromStateToken(provider.GetRequiredService<OpenIddictClientService>())
            .HandleAsync(context);

        // Assert
        Assert.Equal("tenant1", context.RegistrationId);
        Assert.Equal("tenant1", context.Registration.RegistrationId);
        Assert.Equal(DynamicIssuer, context.Configuration.Issuer);
    }

    private static OpenIddictClientTransaction CreateTransaction(IServiceProvider provider) => new()
    {
        CancellationToken = CancellationToken.None,
        Options = provider.GetRequiredService<IOptionsMonitor<OpenIddictClientOptions>>().CurrentValue,
        ServiceProvider = provider
    };

    private static ServiceProvider CreateProvider(
        IOpenIddictClientRegistrationProvider? registrationProvider, Action<OpenIddictClientBuilder>? configuration = null)
    {
        var services = new ServiceCollection();
        services.AddLogging();

        services.AddOpenIddict()
            .AddClient(options =>
            {
                options.AllowAuthorizationCodeFlow();
                options.SetRedirectionEndpointUris("https://localhost/callback");
                options.SetPostLogoutRedirectionEndpointUris("https://localhost/logout");

                options.AddEphemeralEncryptionKey()
                       .AddEphemeralSigningKey();

                if (registrationProvider is not null)
                {
                    options.AddRegistrationProvider(registrationProvider);
                }

                configuration?.Invoke(options);
            });

        return services.BuildServiceProvider();
    }

    private static OpenIddictClientRegistration CreateStaticRegistration() => new()
    {
        ClientId = "Contoso",
        Configuration = new OpenIddictConfiguration { Issuer = StaticIssuer },
        Issuer = StaticIssuer,
        ProviderName = "Static",
        RegistrationId = "static"
    };

    private static OpenIddictClientRegistration CreateDynamicRegistration(
        string? identifier = "tenant1", string providerName = "Tenant1", Uri? redirectUri = null) => new()
    {
        ClientId = "Fabrikam",
        Configuration = new OpenIddictConfiguration { Issuer = DynamicIssuer },
        Issuer = DynamicIssuer,
        ProviderName = providerName,
        RedirectUri = redirectUri,
        RegistrationId = identifier
    };

    private sealed class TestRegistrationProvider(
        Func<OpenIddictClientRegistration> factory, bool matchIdentifier = true) : IOpenIddictClientRegistrationProvider
    {
        public int FindByIdCalls { get; private set; }

        public ValueTask<OpenIddictClientRegistration?> FindByIdAsync(string identifier, CancellationToken cancellationToken)
        {
            FindByIdCalls++;

            // Note: a new instance is deliberately returned for each call (e.g like a database-backed provider).
            var registration = factory();
            return new(!matchIdentifier || string.Equals(registration.RegistrationId, identifier, StringComparison.Ordinal)
                ? registration : null);
        }

        public ValueTask<ImmutableArray<OpenIddictClientRegistration>> FindByIssuerAsync(Uri issuer, CancellationToken cancellationToken)
            => new(factory() is var registration && registration.Issuer == issuer ? [registration] : []);

        public ValueTask<ImmutableArray<OpenIddictClientRegistration>> FindByProviderNameAsync(string name, CancellationToken cancellationToken)
            => new(factory() is var registration && string.Equals(registration.ProviderName, name, StringComparison.Ordinal) ? [registration] : []);

        public ValueTask<ImmutableArray<OpenIddictClientRegistration>> ListAsync(CancellationToken cancellationToken)
            => new([factory()]);
    }

    private sealed class MutableTimeProvider(DateTimeOffset now) : TimeProvider
    {
        public DateTimeOffset Now { get; set; } = now;

        public override DateTimeOffset GetUtcNow() => Now;
    }
}
