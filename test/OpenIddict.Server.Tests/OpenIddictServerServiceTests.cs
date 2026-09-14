using System.Security.Claims;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Moq;
using Xunit;
using static OpenIddict.Abstractions.OpenIddictExceptions;
using static OpenIddict.Server.OpenIddictServerEvents;

namespace OpenIddict.Server.Tests;

public class OpenIddictServerServiceTests
{
    private const string Identifier = "3E228451-1555-46F7-A471-951EFBA23A56";

    [Fact]
    public async Task ListPendingBackchannelAuthenticationRequestsAsync_ReturnsPendingRequests()
    {
        // Arrange
        var token = new object();
        var (provider, _) = await CreateProviderAsync(token, Statuses.Inactive);
        var service = provider.GetRequiredService<OpenIddictServerService>();

        // Act
        var requests = new List<OpenIddictServerBackchannelAuthenticationRequest>();
        await foreach (var request in service.ListPendingBackchannelAuthenticationRequestsAsync("Bob"))
        {
            requests.Add(request);
        }

        // Assert
        var result = Assert.Single(requests);
        Assert.Equal(Identifier, result.Identifier);
        Assert.Equal("Fabrikam", result.ClientId);
        Assert.Equal("W4SCT", result.BindingMessage);
        Assert.Equal("Bob", result.Subject);
        Assert.Equal([Scopes.OpenId, Scopes.Profile], result.Scopes.ToArray());
    }

    [Theory]
    [InlineData(Statuses.Valid)]
    [InlineData(Statuses.Rejected)]
    [InlineData(Statuses.Redeemed)]
    public async Task GetPendingBackchannelAuthenticationRequestAsync_ReturnsNullForNonPendingRequests(string status)
    {
        // Arrange
        var token = new object();
        var (provider, _) = await CreateProviderAsync(token, status);
        var service = provider.GetRequiredService<OpenIddictServerService>();

        // Act and assert
        Assert.Null(await service.GetPendingBackchannelAuthenticationRequestAsync(Identifier));
    }

    [Fact]
    public async Task ApproveBackchannelAuthenticationRequestAsync_UpdatesTokenEntry()
    {
        // Arrange
        var token = new object();
        var (provider, manager) = await CreateProviderAsync(token, Statuses.Inactive);
        var service = provider.GetRequiredService<OpenIddictServerService>();

        OpenIddictTokenDescriptor? descriptor = null;
        manager.Setup(manager => manager.UpdateAsync(token, It.IsAny<OpenIddictTokenDescriptor>(), It.IsAny<CancellationToken>()))
            .Callback((object _, OpenIddictTokenDescriptor value, CancellationToken _) => descriptor = value)
            .Returns(ValueTask.CompletedTask);

        var principal = new ClaimsPrincipal(new ClaimsIdentity("Bearer"))
            .SetClaim(Claims.Subject, "Bob")
            .SetClaim(Claims.Name, "Bob le Bricoleur");

        // Act
        var result = await service.ApproveBackchannelAuthenticationRequestAsync(Identifier, principal);

        // Assert
        Assert.True(result);
        Assert.NotNull(descriptor);
        Assert.Equal(Statuses.Valid, descriptor.Status);
        Assert.Equal("Bob", descriptor.Subject);
        Assert.NotNull(descriptor.Payload);

        var options = provider.GetRequiredService<IOptionsMonitor<OpenIddictServerOptions>>().CurrentValue;
        var parameters = options.TokenValidationParameters.Clone();
        parameters.ValidIssuer = "https://www.contoso.com/";

        var validation = await options.JsonWebTokenHandler.ValidateTokenAsync(descriptor.Payload, parameters);
        Assert.True(validation.IsValid, validation.Exception?.Message);

        var approved = new ClaimsPrincipal(validation.ClaimsIdentity);
        Assert.Equal("Bob le Bricoleur", approved.GetClaim(Claims.Name));
        Assert.Equal(Identifier, approved.GetTokenId());
        Assert.Equal("W4SCT", approved.GetClaim(Claims.Private.BindingMessage));
        Assert.True(approved.HasPresenter("Fabrikam"));
    }

    [Fact]
    public async Task ApproveBackchannelAuthenticationRequestAsync_ThrowsAnExceptionForDifferentSubject()
    {
        // Arrange
        var token = new object();
        var (provider, _) = await CreateProviderAsync(token, Statuses.Inactive);
        var service = provider.GetRequiredService<OpenIddictServerService>();

        var principal = new ClaimsPrincipal(new ClaimsIdentity("Bearer")).SetClaim(Claims.Subject, "Alice");

        // Act and assert
        var exception = await Assert.ThrowsAsync<InvalidOperationException>(
            async () => await service.ApproveBackchannelAuthenticationRequestAsync(Identifier, principal));

        Assert.Equal(SR.GetResourceString(SR.ID0534), exception.Message);
    }

    [Fact]
    public async Task ApproveBackchannelAuthenticationRequestAsync_ReturnsFalseForConcurrentUpdates()
    {
        // Arrange
        var token = new object();
        var (provider, manager) = await CreateProviderAsync(token, Statuses.Inactive);
        var service = provider.GetRequiredService<OpenIddictServerService>();

        manager.Setup(manager => manager.UpdateAsync(token, It.IsAny<OpenIddictTokenDescriptor>(), It.IsAny<CancellationToken>()))
            .Returns(new ValueTask(Task.FromException(new ConcurrencyException("concurrency"))));

        // Act and assert
        Assert.False(await service.ApproveBackchannelAuthenticationRequestAsync(Identifier));
    }

    [Fact]
    public async Task ApproveBackchannelAuthenticationRequestAsync_ReturnsFalseForNonPendingRequests()
    {
        // Arrange
        var token = new object();
        var (provider, manager) = await CreateProviderAsync(token, Statuses.Valid);
        var service = provider.GetRequiredService<OpenIddictServerService>();

        // Act and assert
        Assert.False(await service.ApproveBackchannelAuthenticationRequestAsync(Identifier));

        manager.Verify(manager => manager.UpdateAsync(token, It.IsAny<OpenIddictTokenDescriptor>(), It.IsAny<CancellationToken>()), Times.Never());
    }

    [Fact]
    public async Task RejectBackchannelAuthenticationRequestAsync_RejectsTokenEntry()
    {
        // Arrange
        var token = new object();
        var (provider, manager) = await CreateProviderAsync(token, Statuses.Inactive);
        var service = provider.GetRequiredService<OpenIddictServerService>();

        manager.Setup(manager => manager.TryRejectAsync(token, It.IsAny<CancellationToken>()))
            .ReturnsAsync(true);

        // Act and assert
        Assert.True(await service.RejectBackchannelAuthenticationRequestAsync(Identifier));

        manager.Verify(manager => manager.TryRejectAsync(token, It.IsAny<CancellationToken>()), Times.Once());
    }

    private static async Task<(ServiceProvider Provider, Mock<IOpenIddictTokenManager> Manager)> CreateProviderAsync(object token, string status)
    {
        var manager = new Mock<IOpenIddictTokenManager>();

        var services = new ServiceCollection();
        services.AddSingleton(manager.Object);

        services.AddOpenIddict()
            .AddServer(options =>
            {
                options.SetTokenEndpointUris("connect/token")
                       .SetBackchannelAuthenticationEndpointUris("connect/ciba")
                       .AllowClientInitiatedBackchannelAuthenticationFlow()
                       .SetIssuer(new Uri("https://www.contoso.com/", UriKind.Absolute));

                options.AddEphemeralEncryptionKey()
                       .AddEphemeralSigningKey();

                options.DisableAuthorizationStorage();
            });

        var provider = services.BuildServiceProvider();

        var options = provider.GetRequiredService<IOptionsMonitor<OpenIddictServerOptions>>().CurrentValue;

        // Generate the payload of the pending authentication request using the server token generation pipeline.
        var context = new GenerateTokenContext(new OpenIddictServerTransaction
        {
            CancellationToken = CancellationToken.None,
            Options = options,
            ServiceProvider = provider
        })
        {
            ClientId = "Fabrikam",
            CreateTokenEntry = false,
            IsReferenceToken = false,
            PersistTokenPayload = false,
            Principal = new ClaimsPrincipal(new ClaimsIdentity("Bearer"))
                .SetClaim(Claims.Subject, "Bob")
                .SetClaim(Claims.Private.BindingMessage, "W4SCT")
                .SetClaim(Claims.Private.Issuer, "https://www.contoso.com/")
                .SetPresenters("Fabrikam")
                .SetScopes(Scopes.OpenId, Scopes.Profile)
                .SetTokenId(Identifier),
            TokenFormat = TokenFormats.Private.JsonWebToken,
            TokenType = TokenTypeIdentifiers.Private.AuthenticationRequestId
        };

        await provider.GetRequiredService<IOpenIddictServerDispatcher>().DispatchAsync(context);
        Assert.False(string.IsNullOrEmpty(context.Token));
        Assert.True(new JsonWebTokenHandler().CanReadToken(context.Token));

        manager.Setup(manager => manager.FindByIdAsync(Identifier, It.IsAny<CancellationToken>()))
            .ReturnsAsync(token);

        manager.Setup(manager => manager.FindBySubjectAsync("Bob", It.IsAny<CancellationToken>()))
            .Returns(ListAsync());

        manager.Setup(manager => manager.GetIdAsync(token, It.IsAny<CancellationToken>()))
            .ReturnsAsync(Identifier);

        manager.Setup(manager => manager.HasTypeAsync(token, TokenTypeIdentifiers.Private.AuthenticationRequestId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(true);

        manager.Setup(manager => manager.HasStatusAsync(token, It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync((object _, string value, CancellationToken _) => string.Equals(value, status, StringComparison.Ordinal));

        manager.Setup(manager => manager.GetExpirationDateAsync(token, It.IsAny<CancellationToken>()))
            .ReturnsAsync(DateTimeOffset.UtcNow + TimeSpan.FromMinutes(5));

        manager.Setup(manager => manager.GetCreationDateAsync(token, It.IsAny<CancellationToken>()))
            .ReturnsAsync(DateTimeOffset.UtcNow);

        manager.Setup(manager => manager.GetPayloadAsync(token, It.IsAny<CancellationToken>()))
            .ReturnsAsync(context.Token);

        return (provider, manager);

        async IAsyncEnumerable<object> ListAsync()
        {
            await Task.Yield();
            yield return token;
        }
    }
}
