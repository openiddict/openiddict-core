/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Collections.Immutable;
using System.ComponentModel.DataAnnotations;
using System.Runtime.CompilerServices;
using System.Security.Claims;
using System.Text.Json;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Xunit;
using static OpenIddict.Server.OpenIddictServerEvents;

namespace OpenIddict.Server.IntegrationTests;

public abstract partial class OpenIddictServerIntegrationTests
{
    [Fact]
    public async Task AutomaticKeyManagement_TokensAreSignedWithPublishedKey()
    {
        // Arrange
        var manager = new InMemoryKeyManager();

        await using var server = await CreateServerAsync(options =>
        {
            options.EnableDegradedMode();
            options.DisableAccessTokenEncryption();
            options.EnableAutomaticKeyManagement();

            options.Configure(options =>
            {
                options.EncryptionCredentials.Clear();
                options.SigningCredentials.Clear();
            });

            options.Services.AddSingleton<IOpenIddictKeyManager>(manager);
            options.Services.AddSingleton<IOpenIddictServerKeyProtector, IdentityKeyProtector>();

            options.AddEventHandler<HandleTokenRequestContext>(builder =>
                builder.UseInlineHandler(context =>
                {
                    context.Principal = new ClaimsPrincipal(new ClaimsIdentity("Bearer"))
                        .SetClaim(Claims.Subject, "Bob le Magnifique");

                    return ValueTask.CompletedTask;
                }));
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/connect/token", new OpenIddictRequest
        {
            GrantType = GrantTypes.Password,
            Username = "johndoe",
            Password = "A3ddj3w"
        });

        var keys = await client.GetAsync("/.well-known/jwks");

        // Assert
        Assert.NotNull(response.AccessToken);

        var signing = Assert.Single(manager.Keys, static key => key.Usage is JsonWebKeyUseNames.Sig);
        Assert.Single(manager.Keys, static key => key.Usage is JsonWebKeyUseNames.Enc);

        var set = new JsonWebKeySet(keys.ToString());
        Assert.Equal(signing.KeyId, Assert.Single(set.Keys).Kid);

        var result = await new JsonWebTokenHandler().ValidateTokenAsync(response.AccessToken, new TokenValidationParameters
        {
            IssuerSigningKeys = set.GetSigningKeys(),
            ValidateAudience = false,
            ValidateIssuer = false
        });

        Assert.True(result.IsValid);
        Assert.Equal(signing.KeyId, ((JsonWebToken) result.SecurityToken).Kid);
    }

    private sealed class IdentityKeyProtector : IOpenIddictServerKeyProtector
    {
        public string Protect(string payload) => payload;

        public string Unprotect(string payload) => payload;
    }

    private sealed class InMemoryKeyManager : IOpenIddictKeyManager
    {
        public List<OpenIddictKeyDescriptor> Keys { get; } = [];

        public ValueTask<long> CountAsync(CancellationToken cancellationToken = default) => new(Keys.Count);

        public ValueTask<object> CreateAsync(OpenIddictKeyDescriptor descriptor, CancellationToken cancellationToken = default)
        {
            lock (Keys)
            {
                Keys.Add(descriptor);
            }

            return new(descriptor);
        }

        public ValueTask CreateAsync(object key, CancellationToken cancellationToken = default) => throw new NotSupportedException();
        public ValueTask DeleteAsync(object key, CancellationToken cancellationToken = default) => throw new NotSupportedException();
        public ValueTask<object?> FindByIdAsync(string identifier, CancellationToken cancellationToken = default) => throw new NotSupportedException();
        public ValueTask<DateTimeOffset?> GetActivationDateAsync(object key, CancellationToken cancellationToken = default) => new(((OpenIddictKeyDescriptor) key).ActivationDate);
        public ValueTask<string?> GetAlgorithmAsync(object key, CancellationToken cancellationToken = default) => new(((OpenIddictKeyDescriptor) key).Algorithm);
        public ValueTask<DateTimeOffset?> GetCreationDateAsync(object key, CancellationToken cancellationToken = default) => new(((OpenIddictKeyDescriptor) key).CreationDate);
        public ValueTask<DateTimeOffset?> GetExpirationDateAsync(object key, CancellationToken cancellationToken = default) => new(((OpenIddictKeyDescriptor) key).ExpirationDate);
        public ValueTask<string?> GetIdAsync(object key, CancellationToken cancellationToken = default) => new(((OpenIddictKeyDescriptor) key).KeyId);
        public ValueTask<string?> GetKeyIdAsync(object key, CancellationToken cancellationToken = default) => new(((OpenIddictKeyDescriptor) key).KeyId);
        public ValueTask<string?> GetPayloadAsync(object key, CancellationToken cancellationToken = default) => new(((OpenIddictKeyDescriptor) key).Payload);
        public ValueTask<ImmutableDictionary<string, JsonElement>> GetPropertiesAsync(object key, CancellationToken cancellationToken = default) => new([]);
        public ValueTask<DateTimeOffset?> GetRetirementDateAsync(object key, CancellationToken cancellationToken = default) => new(((OpenIddictKeyDescriptor) key).RetirementDate);
        public ValueTask<string?> GetStatusAsync(object key, CancellationToken cancellationToken = default) => new(((OpenIddictKeyDescriptor) key).Status);
        public ValueTask<string?> GetUsageAsync(object key, CancellationToken cancellationToken = default) => new(((OpenIddictKeyDescriptor) key).Usage);

        public ValueTask<bool> HasStatusAsync(object key, string status, CancellationToken cancellationToken = default)
            => new(string.Equals(((OpenIddictKeyDescriptor) key).Status, status, StringComparison.Ordinal));

        public async IAsyncEnumerable<object> ListAsync(int? count = null, int? offset = null,
            [EnumeratorCancellation] CancellationToken cancellationToken = default)
        {
            OpenIddictKeyDescriptor[] keys;

            lock (Keys)
            {
                keys = [.. Keys];
            }

            foreach (var key in keys)
            {
                await Task.Yield();
                yield return key;
            }
        }

        public ValueTask PopulateAsync(OpenIddictKeyDescriptor descriptor, object key, CancellationToken cancellationToken = default) => throw new NotSupportedException();
        public ValueTask PopulateAsync(object key, OpenIddictKeyDescriptor descriptor, CancellationToken cancellationToken = default) => throw new NotSupportedException();
        public ValueTask<long> PruneAsync(DateTimeOffset threshold, CancellationToken cancellationToken = default) => throw new NotSupportedException();
        public ValueTask<bool> TryRevokeAsync(object key, CancellationToken cancellationToken = default) => throw new NotSupportedException();
        public ValueTask UpdateAsync(object key, CancellationToken cancellationToken = default) => throw new NotSupportedException();
        public ValueTask UpdateAsync(object key, OpenIddictKeyDescriptor descriptor, CancellationToken cancellationToken = default) => throw new NotSupportedException();
        public IAsyncEnumerable<ValidationResult> ValidateAsync(object key, CancellationToken cancellationToken = default) => throw new NotSupportedException();
    }
}
