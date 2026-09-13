using System.Collections.Immutable;
using System.ComponentModel.DataAnnotations;
using System.Runtime.CompilerServices;
using System.Text.Json;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Xunit;

namespace OpenIddict.Server.Tests;

public class OpenIddictServerKeyRingTests
{
    private static readonly DateTimeOffset Origin = new(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);

    [Fact]
    public async Task GetCredentialsAsync_CreatesActiveSigningAndEncryptionKeys()
    {
        // Arrange
        var (provider, ring, manager, _) = CreateRing();

        // Act
        var credentials = await ring.GetCredentialsAsync(provider);

        // Assert
        Assert.Equal(2, manager.Keys.Count);

        var signing = Assert.Single(manager.Keys, key => key.Usage is "sig");
        Assert.Equal(Origin, signing.ActivationDate);
        Assert.Equal(Origin + TimeSpan.FromDays(90), signing.ExpirationDate);
        Assert.Equal(Origin + TimeSpan.FromDays(104), signing.RetirementDate);
        Assert.Equal(SecurityAlgorithms.RsaSha256, signing.Algorithm);

        Assert.Equal(signing.KeyId, Assert.Single(credentials.SigningCredentials).Key.KeyId);
        Assert.Equal(SecurityAlgorithms.RsaOAEP, Assert.Single(credentials.EncryptionCredentials).Alg);
        Assert.True(Assert.IsType<RsaSecurityKey>(credentials.SigningCredentials[0].Key).PrivateKeyStatus is PrivateKeyStatus.Exists);
    }

    [Fact]
    public async Task GetCredentialsAsync_UsesCachedCredentials()
    {
        // Arrange
        var (provider, ring, manager, _) = CreateRing();
        var credentials = await ring.GetCredentialsAsync(provider);

        // Act and assert
        Assert.Same(credentials, await ring.GetCredentialsAsync(provider));

        // Note: the keys are listed once and reloaded once after being created.
        Assert.Equal(2, manager.ListCount);
    }

    [Fact]
    public async Task GetCredentialsAsync_StaticCredentialsAreUsedAfterTheActiveKey()
    {
        // Arrange
        var key = new SymmetricSecurityKey(new byte[32]) { KeyId = "static" };
        var (provider, ring, _, _) = CreateRing(options => options.SigningCredentials.Add(
            new SigningCredentials(key, SecurityAlgorithms.HmacSha256)));

        // Act
        var credentials = await ring.GetCredentialsAsync(provider);

        // Assert
        Assert.Equal(2, credentials.SigningCredentials.Count);
        Assert.IsType<RsaSecurityKey>(credentials.SigningCredentials[0].Key);
        Assert.Same(key, credentials.SigningCredentials[1].Key);
    }

    [Fact]
    public async Task GetCredentialsAsync_AnnouncesSuccessorBeforeActivatingIt()
    {
        // Arrange
        var (provider, ring, manager, clock) = CreateRing();
        var first = (await ring.GetCredentialsAsync(provider)).SigningCredentials[0].Key.KeyId!;

        // Act
        clock.Now = Origin + TimeSpan.FromDays(77);
        var announced = await ring.GetCredentialsAsync(provider);

        clock.Now = Origin + TimeSpan.FromDays(90);
        var rotated = await ring.GetCredentialsAsync(provider);

        // Assert
        var successor = Assert.Single(manager.Keys, key => key.Usage is "sig" && !string.Equals(key.KeyId, first, StringComparison.Ordinal));
        Assert.Equal(Origin + TimeSpan.FromDays(90), successor.ActivationDate);

        Assert.Equal(new[] { first, successor.KeyId! }, announced.SigningCredentials.Select(static credentials => credentials.Key.KeyId!), StringComparer.Ordinal);
        Assert.Equal(new[] { successor.KeyId!, first }, rotated.SigningCredentials.Select(static credentials => credentials.Key.KeyId!), StringComparer.Ordinal);
    }

    [Fact]
    public async Task GetCredentialsAsync_ExcludesRetiredAndRevokedKeys()
    {
        // Arrange
        var (provider, ring, manager, clock) = CreateRing();
        var first = (await ring.GetCredentialsAsync(provider)).SigningCredentials[0].Key.KeyId;

        clock.Now = Origin + TimeSpan.FromDays(80);
        await ring.GetCredentialsAsync(provider);

        // Act
        clock.Now = Origin + TimeSpan.FromDays(105);
        var retired = await ring.GetCredentialsAsync(provider);

        // Assert
        Assert.DoesNotContain(retired.SigningCredentials, credentials => string.Equals(credentials.Key.KeyId, first, StringComparison.Ordinal));

        // Act
        foreach (var key in manager.Keys)
        {
            key.Status = Statuses.Revoked;
        }

        ring.Invalidate();
        var revoked = await ring.GetCredentialsAsync(provider);

        // Assert
        Assert.Single(revoked.SigningCredentials);
        Assert.DoesNotContain(revoked.SigningCredentials, credentials =>
            manager.Keys.Exists(key => string.Equals(key.KeyId, credentials.Key.KeyId, StringComparison.Ordinal) && key.Status is Statuses.Revoked));
    }

    [Fact]
    public async Task GetCredentialsAsync_ThrowsAnExceptionWhenNoProtectorIsRegistered()
    {
        // Arrange
        var (provider, ring, _, _) = CreateRing(protector: false);

        // Act and assert
        var exception = await Assert.ThrowsAsync<InvalidOperationException>(
            async () => await ring.GetCredentialsAsync(provider));

        Assert.Equal(SR.GetResourceString(SR.ID0542), exception.Message);
    }

    [Fact]
    public async Task ResolveCredentialsAsync_ReturnsStaticCredentialsWhenDisabled()
    {
        // Arrange
        var options = new OpenIddictServerOptions();
        options.SigningCredentials.Add(new SigningCredentials(new SymmetricSecurityKey(new byte[32]), SecurityAlgorithms.HmacSha256));

        var transaction = new OpenIddictServerTransaction
        {
            CancellationToken = CancellationToken.None,
            Options = options,
            ServiceProvider = new ServiceCollection().BuildServiceProvider()
        };

        // Act
        var credentials = await OpenIddictServerKeyRing.ResolveCredentialsAsync(transaction);

        // Assert
        Assert.Same(options.SigningCredentials, credentials.SigningCredentials);
        Assert.Same(credentials, transaction.Credentials);
    }

    private static (ServiceProvider Provider, OpenIddictServerKeyRing Ring, InMemoryKeyManager Manager, MutableTimeProvider Clock) CreateRing(
        Action<OpenIddictServerOptions>? configuration = null, bool protector = true)
    {
        var clock = new MutableTimeProvider { Now = Origin };
        var manager = new InMemoryKeyManager();

        var services = new ServiceCollection();
        services.AddLogging();
        services.AddSingleton<IOpenIddictKeyManager>(manager);
        services.AddSingleton<OpenIddictServerKeyRing>();
        services.Configure<OpenIddictServerOptions>(options =>
        {
            options.EnableAutomaticKeyManagement = true;
            options.TimeProvider = clock;
            configuration?.Invoke(options);
        });

        if (protector)
        {
            services.AddSingleton<IOpenIddictServerKeyProtector, IdentityProtector>();
        }

        var provider = services.BuildServiceProvider();

        return (provider, provider.GetRequiredService<OpenIddictServerKeyRing>(), manager, clock);
    }

    private sealed class MutableTimeProvider : TimeProvider
    {
        public DateTimeOffset Now { get; set; }

        public override DateTimeOffset GetUtcNow() => Now;
    }

    private sealed class IdentityProtector : IOpenIddictServerKeyProtector
    {
        public string Protect(string payload) => payload;

        public string Unprotect(string payload) => payload;
    }

    private sealed class InMemoryKeyManager : IOpenIddictKeyManager
    {
        public List<OpenIddictKeyDescriptor> Keys { get; } = [];

        public int ListCount { get; private set; }

        public ValueTask<long> CountAsync(CancellationToken cancellationToken = default) => new(Keys.Count);

        public ValueTask<object> CreateAsync(OpenIddictKeyDescriptor descriptor, CancellationToken cancellationToken = default)
        {
            Keys.Add(descriptor);
            return new(descriptor);
        }

        public ValueTask CreateAsync(object key, CancellationToken cancellationToken = default)
        {
            Keys.Add((OpenIddictKeyDescriptor) key);
            return ValueTask.CompletedTask;
        }

        public ValueTask DeleteAsync(object key, CancellationToken cancellationToken = default)
        {
            Keys.Remove((OpenIddictKeyDescriptor) key);
            return ValueTask.CompletedTask;
        }

        public ValueTask<object?> FindByIdAsync(string identifier, CancellationToken cancellationToken = default)
            => new(Keys.Find(key => string.Equals(key.KeyId, identifier, StringComparison.Ordinal)));

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
            ListCount++;

            foreach (var key in Keys.ToList())
            {
                await Task.Yield();
                yield return key;
            }
        }

        public ValueTask PopulateAsync(OpenIddictKeyDescriptor descriptor, object key, CancellationToken cancellationToken = default) => throw new NotSupportedException();
        public ValueTask PopulateAsync(object key, OpenIddictKeyDescriptor descriptor, CancellationToken cancellationToken = default) => throw new NotSupportedException();
        public ValueTask<long> PruneAsync(DateTimeOffset threshold, CancellationToken cancellationToken = default) => throw new NotSupportedException();
        public ValueTask<bool> TryRevokeAsync(object key, CancellationToken cancellationToken = default) => throw new NotSupportedException();
        public ValueTask UpdateAsync(object key, CancellationToken cancellationToken = default) => ValueTask.CompletedTask;
        public ValueTask UpdateAsync(object key, OpenIddictKeyDescriptor descriptor, CancellationToken cancellationToken = default) => ValueTask.CompletedTask;
        public IAsyncEnumerable<ValidationResult> ValidateAsync(object key, CancellationToken cancellationToken = default) => throw new NotSupportedException();
    }
}
