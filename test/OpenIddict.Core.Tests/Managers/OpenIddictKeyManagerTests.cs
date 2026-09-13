/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Collections.Immutable;
using System.Runtime.CompilerServices;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Moq;
using Xunit;
using static OpenIddict.Abstractions.OpenIddictExceptions;

namespace OpenIddict.Core.Tests;

public class OpenIddictKeyManagerTests
{
    private static readonly DateTimeOffset Now = new(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);

    [Fact]
    public async Task CreateAsync_AttachesDefaultStatusAndCreationDate()
    {
        // Arrange
        var (manager, store) = CreateManager();
        var descriptor = CreateDescriptor();

        // Act
        var key = await manager.CreateAsync(descriptor);

        // Assert
        Assert.Equal(Statuses.Valid, key.Status);
        Assert.NotNull(key.CreationDate);
        Assert.Same(key, Assert.Single(store.Keys));
    }

    [Theory]
    [InlineData(nameof(OpenIddictKeyDescriptor.KeyId), SR.ID2220)]
    [InlineData(nameof(OpenIddictKeyDescriptor.Payload), SR.ID2221)]
    [InlineData(nameof(OpenIddictKeyDescriptor.Usage), SR.ID2222)]
    [InlineData(nameof(OpenIddictKeyDescriptor.Algorithm), SR.ID2223)]
    [InlineData(nameof(OpenIddictKeyDescriptor.ExpirationDate), SR.ID2224)]
    public async Task CreateAsync_ThrowsAnExceptionForInvalidKey(string property, string message)
    {
        // Arrange
        var (manager, store) = CreateManager();
        var descriptor = CreateDescriptor();
        typeof(OpenIddictKeyDescriptor).GetProperty(property)!.SetValue(descriptor, null);

        // Act and assert
        var exception = await Assert.ThrowsAsync<ValidationException>(async () => await manager.CreateAsync(descriptor));

        Assert.Contains(exception.Results, result => string.Equals(result.ErrorMessage, SR.GetResourceString(message), StringComparison.Ordinal));
        Assert.Empty(store.Keys);
    }

    [Fact]
    public async Task TryRevokeAsync_RevokesKey()
    {
        // Arrange
        var (manager, _) = CreateManager();
        var key = await manager.CreateAsync(CreateDescriptor());

        // Act and assert
        Assert.True(await manager.TryRevokeAsync(key));
        Assert.Equal(Statuses.Revoked, key.Status);
    }

    private static OpenIddictKeyDescriptor CreateDescriptor() => new()
    {
        ActivationDate = Now,
        Algorithm = "RS256",
        ExpirationDate = Now.AddDays(90),
        KeyId = "kid",
        Payload = "payload",
        RetirementDate = Now.AddDays(104),
        Usage = "sig"
    };

    private static (OpenIddictKeyManager<CustomKey> Manager, InMemoryKeyStore Store) CreateManager()
    {
        var store = new InMemoryKeyStore();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>(
            mock => mock.CurrentValue == new OpenIddictCoreOptions { TimeProvider = TimeProvider.System });

        return (new OpenIddictKeyManager<CustomKey>(Mock.Of<ILogger<OpenIddictKeyManager<CustomKey>>>(), options, store), store);
    }

    public sealed class CustomKey
    {
        public DateTimeOffset? ActivationDate { get; set; }
        public string? Algorithm { get; set; }
        public DateTimeOffset? CreationDate { get; set; }
        public DateTimeOffset? ExpirationDate { get; set; }
        public string? KeyId { get; set; }
        public string? Payload { get; set; }
        public DateTimeOffset? RetirementDate { get; set; }
        public string? Status { get; set; }
        public string? Usage { get; set; }
    }

    private sealed class InMemoryKeyStore : IOpenIddictKeyStore<CustomKey>
    {
        public List<CustomKey> Keys { get; } = [];

        public ValueTask<long> CountAsync(CancellationToken cancellationToken) => new(Keys.Count);
        public ValueTask CreateAsync(CustomKey key, CancellationToken cancellationToken) { Keys.Add(key); return default; }
        public ValueTask DeleteAsync(CustomKey key, CancellationToken cancellationToken) { Keys.Remove(key); return default; }
        public ValueTask<CustomKey?> FindByIdAsync(string identifier, CancellationToken cancellationToken)
            => new(Keys.Find(key => string.Equals(key.KeyId, identifier, StringComparison.Ordinal)));
        public ValueTask<DateTimeOffset?> GetActivationDateAsync(CustomKey key, CancellationToken cancellationToken) => new(key.ActivationDate);
        public ValueTask<string?> GetAlgorithmAsync(CustomKey key, CancellationToken cancellationToken) => new(key.Algorithm);
        public ValueTask<DateTimeOffset?> GetCreationDateAsync(CustomKey key, CancellationToken cancellationToken) => new(key.CreationDate);
        public ValueTask<DateTimeOffset?> GetExpirationDateAsync(CustomKey key, CancellationToken cancellationToken) => new(key.ExpirationDate);
        public ValueTask<string?> GetIdAsync(CustomKey key, CancellationToken cancellationToken) => new(key.KeyId);
        public ValueTask<string?> GetKeyIdAsync(CustomKey key, CancellationToken cancellationToken) => new(key.KeyId);
        public ValueTask<string?> GetPayloadAsync(CustomKey key, CancellationToken cancellationToken) => new(key.Payload);
        public ValueTask<ImmutableDictionary<string, JsonElement>> GetPropertiesAsync(CustomKey key, CancellationToken cancellationToken) => new([]);
        public ValueTask<DateTimeOffset?> GetRetirementDateAsync(CustomKey key, CancellationToken cancellationToken) => new(key.RetirementDate);
        public ValueTask<string?> GetStatusAsync(CustomKey key, CancellationToken cancellationToken) => new(key.Status);
        public ValueTask<string?> GetUsageAsync(CustomKey key, CancellationToken cancellationToken) => new(key.Usage);
        public ValueTask<CustomKey> InstantiateAsync(CancellationToken cancellationToken) => new(new CustomKey());

        public async IAsyncEnumerable<CustomKey> ListAsync(int? count, int? offset, [EnumeratorCancellation] CancellationToken cancellationToken)
        {
            foreach (var key in Keys)
            {
                await Task.Yield();
                yield return key;
            }
        }

        public ValueTask<long> PruneAsync(DateTimeOffset threshold, CancellationToken cancellationToken) => new(0);
        public ValueTask SetActivationDateAsync(CustomKey key, DateTimeOffset? date, CancellationToken cancellationToken) { key.ActivationDate = date; return default; }
        public ValueTask SetAlgorithmAsync(CustomKey key, string? algorithm, CancellationToken cancellationToken) { key.Algorithm = algorithm; return default; }
        public ValueTask SetCreationDateAsync(CustomKey key, DateTimeOffset? date, CancellationToken cancellationToken) { key.CreationDate = date; return default; }
        public ValueTask SetExpirationDateAsync(CustomKey key, DateTimeOffset? date, CancellationToken cancellationToken) { key.ExpirationDate = date; return default; }
        public ValueTask SetKeyIdAsync(CustomKey key, string? identifier, CancellationToken cancellationToken) { key.KeyId = identifier; return default; }
        public ValueTask SetPayloadAsync(CustomKey key, string? payload, CancellationToken cancellationToken) { key.Payload = payload; return default; }
        public ValueTask SetPropertiesAsync(CustomKey key, ImmutableDictionary<string, JsonElement> properties, CancellationToken cancellationToken) => default;
        public ValueTask SetRetirementDateAsync(CustomKey key, DateTimeOffset? date, CancellationToken cancellationToken) { key.RetirementDate = date; return default; }
        public ValueTask SetStatusAsync(CustomKey key, string? status, CancellationToken cancellationToken) { key.Status = status; return default; }
        public ValueTask SetUsageAsync(CustomKey key, string? usage, CancellationToken cancellationToken) { key.Usage = usage; return default; }
        public ValueTask UpdateAsync(CustomKey key, CancellationToken cancellationToken) => default;
    }
}
