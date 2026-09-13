/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Xunit;
using static OpenIddict.Validation.OpenIddictValidationEvents;
using static OpenIddict.Validation.OpenIddictValidationHandlers.Introspection;
using static OpenIddict.Validation.SystemNetHttp.OpenIddictValidationSystemNetHttpHandlers.Introspection;

namespace OpenIddict.Validation.Tests;

public class OpenIddictValidationHandlersIntrospectionResponseTests
{
    private const string Issuer = "https://www.contoso.com/";

    private static readonly RsaSecurityKey ServerSigningKey = new(RSA.Create(keySizeInBits: 2048)) { KeyId = "server_key" };

    [Fact]
    public async Task ValidateIntrospectionResponseToken_ResponseIsExtractedFromValidToken()
    {
        // Arrange
        using var provider = CreateProvider(required: true);
        var context = CreateContext(provider, CreateToken());

        // Act
        await CreateHandler(provider).HandleAsync(context);

        // Assert
        Assert.False(context.IsRejected);
        Assert.True((bool) context.Response[Claims.Active]);
        Assert.Equal("Bob le Magnifique", (string?) context.Response[Claims.Subject]);
    }

    [Fact]
    public async Task ValidateIntrospectionResponseToken_EncryptedTokenIsDecryptedUsingValidationKeys()
    {
        // Arrange
        using var provider = CreateProvider(required: true);
        var options = provider.GetRequiredService<IOptionsMonitor<OpenIddictValidationOptions>>().CurrentValue;

        var context = CreateContext(provider, CreateToken(encryption: new EncryptingCredentials(
            options.EncryptionCredentials[0].Key, SecurityAlgorithms.RsaOAEP, SecurityAlgorithms.Aes256CbcHmacSha512)));

        // Act
        await CreateHandler(provider).HandleAsync(context);

        // Assert
        Assert.False(context.IsRejected);
        Assert.True((bool) context.Response[Claims.Active]);
    }

    [Theory]
    [InlineData(JsonWebTokenTypes.GenericJsonWebToken, Issuer, false)]
    [InlineData(JsonWebTokenTypes.IntrospectionResponse, "https://www.fabrikam.com/", false)]
    [InlineData(JsonWebTokenTypes.IntrospectionResponse, Issuer, true)]
    public async Task ValidateIntrospectionResponseToken_InvalidTokenIsRejected(string type, string issuer, bool untrusted)
    {
        // Arrange
        using var provider = CreateProvider(required: true);
        var context = CreateContext(provider, CreateToken(type: type, issuer: issuer, signing: untrusted
            ? new SigningCredentials(new RsaSecurityKey(RSA.Create(keySizeInBits: 2048)) { KeyId = "server_key" }, SecurityAlgorithms.RsaSha256)
            : null));

        // Act
        await CreateHandler(provider).HandleAsync(context);

        // Assert
        Assert.True(context.IsRejected);
        Assert.Equal(Errors.ServerError, context.Error);
        Assert.Equal(SR.GetResourceString(SR.ID2236), context.ErrorDescription);
    }

    [Fact]
    public async Task ValidateIntrospectionResponseToken_TokenIssuedToAnotherResourceServerIsRejected()
    {
        // Arrange
        using var provider = CreateProvider(required: true);
        var context = CreateContext(provider, CreateToken(audience: "Contoso"));

        // Act
        await CreateHandler(provider).HandleAsync(context);

        // Assert
        Assert.True(context.IsRejected);
        Assert.Equal(SR.GetResourceString(SR.ID2237), context.ErrorDescription);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("\"active\"")]
    public async Task ValidateIntrospectionResponseToken_TokenWithoutValidIntrospectionClaimIsRejected(string? claim)
    {
        // Arrange
        using var provider = CreateProvider(required: true);
        var context = CreateContext(provider, CreateToken(introspection: claim));

        // Act
        await CreateHandler(provider).HandleAsync(context);

        // Assert
        Assert.True(context.IsRejected);
        Assert.Equal(SR.FormatID2238(Claims.TokenIntrospection), context.ErrorDescription);
    }

    [Fact]
    public async Task ValidateIntrospectionResponseToken_JsonResponseIsRejectedWhenTokenIsRequired()
    {
        // Arrange
        using var provider = CreateProvider(required: true);
        var context = CreateContext(provider, token: null);
        context.Response = new OpenIddictResponse { [Claims.Active] = true };

        // Act
        await CreateHandler(provider).HandleAsync(context);

        // Assert
        Assert.True(context.IsRejected);
        Assert.Equal(SR.GetResourceString(SR.ID2235), context.ErrorDescription);
    }

    [Theory]
    [InlineData(true, Errors.InvalidClient)]
    [InlineData(false, null)]
    public async Task ValidateIntrospectionResponseToken_JsonResponseIsAcceptedWhenAllowed(bool required, string? error)
    {
        // Arrange
        using var provider = CreateProvider(required);
        var context = CreateContext(provider, token: null);
        context.Response = new OpenIddictResponse { [Claims.Active] = true, Error = error };

        // Act
        await CreateHandler(provider).HandleAsync(context);

        // Assert
        Assert.False(context.IsRejected);
    }

    [Theory]
    [InlineData(true, "application/token-introspection+jwt")]
    [InlineData(false, "application/json")]
    public async Task AttachIntrospectionResponseAcceptHeader_MediaTypeIsAttachedWhenRequired(bool required, string expected)
    {
        // Arrange
        using var provider = CreateProvider(required);
        var options = provider.GetRequiredService<IOptionsMonitor<OpenIddictValidationOptions>>().CurrentValue;

        using var message = new HttpRequestMessage(HttpMethod.Post, "https://www.contoso.com/connect/introspect");
        message.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));

        var transaction = new OpenIddictValidationTransaction
        {
            CancellationToken = CancellationToken.None,
            Options = options,
            ServiceProvider = provider
        };

        transaction.SetProperty(typeof(HttpRequestMessage).FullName!, message);

        var context = new PrepareIntrospectionRequestContext(transaction)
        {
            RemoteUri = new Uri("https://www.contoso.com/connect/introspect"),
            Request = new OpenIddictRequest()
        };

        // Act
        await new AttachIntrospectionResponseAcceptHeader().HandleAsync(context);

        // Assert
        Assert.Equal(expected, Assert.Single(message.Headers.Accept).MediaType);
    }

    [Fact]
    public async Task ExtractIntrospectionTokenHttpResponse_TokenIsExtractedFromResponse()
    {
        // Arrange
        using var provider = CreateProvider(required: true);
        var options = provider.GetRequiredService<IOptionsMonitor<OpenIddictValidationOptions>>().CurrentValue;

        using var message = new HttpResponseMessage
        {
            Content = new StringContent("token", Encoding.UTF8, "application/token-introspection+jwt")
        };

        var transaction = new OpenIddictValidationTransaction
        {
            CancellationToken = CancellationToken.None,
            Options = options,
            ServiceProvider = provider
        };

        transaction.SetProperty(typeof(HttpResponseMessage).FullName!, message);

        var context = new ExtractIntrospectionResponseContext(transaction)
        {
            RemoteUri = new Uri("https://www.contoso.com/connect/introspect"),
            Request = new OpenIddictRequest()
        };

        // Act
        await new ExtractIntrospectionTokenHttpResponse().HandleAsync(context);

        // Assert
        Assert.Equal("token", context.IntrospectionResponseToken);
        Assert.NotNull(context.Response);
    }

    private static ValidateIntrospectionResponseToken CreateHandler(IServiceProvider provider)
        => new(provider.GetRequiredService<IOpenIddictValidationDispatcher>());

    private static string CreateToken(
        string type = JsonWebTokenTypes.IntrospectionResponse,
        string issuer = Issuer,
        string audience = "Fabrikam",
        string? introspection = """{"active":true,"sub":"Bob le Magnifique"}""",
        SigningCredentials? signing = null,
        EncryptingCredentials? encryption = null)
    {
        var claims = new Dictionary<string, object>(StringComparer.Ordinal)
        {
            [Claims.Audience] = audience,
            [Claims.IssuedAt] = DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
            [Claims.Issuer] = issuer
        };

        if (introspection is not null)
        {
            claims[Claims.TokenIntrospection] = System.Text.Json.JsonDocument.Parse(introspection).RootElement.Clone();
        }

        return new JsonWebTokenHandler { SetDefaultTimesOnTokenCreation = false }.CreateToken(new SecurityTokenDescriptor
        {
            Claims = claims,
            EncryptingCredentials = encryption,
            SigningCredentials = signing ?? new SigningCredentials(ServerSigningKey, SecurityAlgorithms.RsaSha256),
            TokenType = type
        });
    }

    private static HandleIntrospectionResponseContext CreateContext(IServiceProvider provider, string? token)
    {
        var options = provider.GetRequiredService<IOptionsMonitor<OpenIddictValidationOptions>>().CurrentValue;

        var transaction = new OpenIddictValidationTransaction
        {
            CancellationToken = CancellationToken.None,
            Options = options,
            ServiceProvider = provider
        };

        var configuration = new OpenIddictConfiguration { Issuer = new Uri(Issuer, UriKind.Absolute) };
        configuration.SigningKeys.Add(ServerSigningKey);

        return new HandleIntrospectionResponseContext(transaction)
        {
            Configuration = configuration,
            IntrospectionResponseToken = token,
            Request = new OpenIddictRequest(),
            Response = new OpenIddictResponse()
        };
    }

    private static ServiceProvider CreateProvider(bool required)
    {
        var services = new ServiceCollection();

        services.AddOpenIddict()
            .AddValidation(options =>
            {
                options.AddEncryptionKey(new RsaSecurityKey(RSA.Create(keySizeInBits: 2048)));

                options.SetClientId("Fabrikam")
                       .SetClientSecret("7Fjfp0ZBr1KtDRbnfVdmIw")
                       .SetIssuer(Issuer);

                options.UseIntrospection()
                       .UseSystemNetHttp();

                if (required)
                {
                    options.RequireJsonWebTokenIntrospectionResponses();
                }
            });

        return services.BuildServiceProvider();
    }
}
