/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

#if NETFRAMEWORK
using System.Data.Common;
using System.Data.Entity;
using System.Data.Entity.Core.Common;
using System.Data.SQLite;
using System.Data.SQLite.EF6;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Options;
using Moq;
using OpenIddict.EntityFramework.Models;
using SQLite.CodeFirst;
using Xunit;
using static OpenIddict.Abstractions.OpenIddictExceptions;

namespace OpenIddict.EntityFramework.Tests;

public sealed class OpenIddictEntityFrameworkTokenStoreTests : IDisposable
{
    private readonly string _path = Path.Combine(Path.GetTempPath(), $"openiddict-ef6-{Guid.NewGuid():N}.sqlite3");

    [Fact]
    public async Task CreateAsync_EntriesWithoutReferenceIdentifierCanBeCreated()
    {
        // Arrange
        using (var context = CreateContext())
        {
            var store = CreateStore(context);

            // Act
            await store.CreateAsync(new OpenIddictEntityFrameworkToken { Type = "type" }, CancellationToken.None);
            await store.CreateAsync(new OpenIddictEntityFrameworkToken { Type = "type" }, CancellationToken.None);
        }

        // Assert
        using (var context = CreateContext())
        {
            Assert.Equal(2, await context.Set<OpenIddictEntityFrameworkToken>().CountAsync());
        }
    }

    [Fact]
    public async Task CreateAsync_ThrowsAnExceptionForDuplicateReferenceIdentifier()
    {
        // Arrange
        using (var context = CreateContext())
        {
            await CreateStore(context).CreateAsync(new OpenIddictEntityFrameworkToken { ReferenceId = "reference" }, CancellationToken.None);
        }

        using (var context = CreateContext())
        {
            var store = CreateStore(context);

            // Act and assert
            var exception = await Assert.ThrowsAsync<ConcurrencyException>(async () =>
                await store.CreateAsync(new OpenIddictEntityFrameworkToken { ReferenceId = "reference" }, CancellationToken.None));

            Assert.Equal(SR.GetResourceString(SR.ID0986), exception.Message);
        }

        using (var context = CreateContext())
        {
            Assert.Equal(1, await context.Set<OpenIddictEntityFrameworkToken>().CountAsync());
        }
    }

    [Fact]
    public async Task CreateAsync_AtMostOneConcurrentEntryWithSameReferenceIdentifierIsCreated()
    {
        // Arrange
        using (var context = CreateContext())
        {
            // Ensure the database is created before starting the concurrent operations.
            Assert.Equal(0, await context.Set<OpenIddictEntityFrameworkToken>().CountAsync());
        }

        var tasks = Enumerable.Range(0, 8).Select(_ => Task.Run(async () =>
        {
            using var context = CreateContext();

            try
            {
                await CreateStore(context).CreateAsync(new OpenIddictEntityFrameworkToken { ReferenceId = "proof" }, CancellationToken.None);
                return true;
            }

            catch (Exception)
            {
                return false;
            }
        })).ToArray();

        // Act
        await Task.WhenAll(tasks);

        // Assert
        using var verification = CreateContext();
        Assert.Equal(1, await verification.Set<OpenIddictEntityFrameworkToken>().CountAsync(static token => token.ReferenceId == "proof"));
        Assert.InRange(tasks.Count(static task => task.Result), 0, 1);
    }

    public void Dispose()
    {
        SQLiteConnection.ClearAllPools();

        try
        {
            File.Delete(_path);
        }

        catch (IOException)
        {
        }
    }

    private TestContext CreateContext() => new(new SQLiteConnection($"Data Source={_path};Version=3;BusyTimeout=10000"));

    private static OpenIddictEntityFrameworkTokenStore CreateStore(TestContext context) => new(
        new MemoryCache(new MemoryCacheOptions()),
        new OpenIddictEntityFrameworkContext<TestContext>(context),
        Mock.Of<IOptionsMonitor<OpenIddictEntityFrameworkOptions>>(monitor =>
            monitor.CurrentValue == new OpenIddictEntityFrameworkOptions()));

    [DbConfigurationType(typeof(TestConfiguration))]
    public sealed class TestContext(DbConnection connection) : DbContext(connection, contextOwnsConnection: true)
    {
        protected override void OnModelCreating(DbModelBuilder modelBuilder)
        {
            base.OnModelCreating(modelBuilder);

            modelBuilder.UseOpenIddict();

            Database.SetInitializer(new SqliteCreateDatabaseIfNotExists<TestContext>(modelBuilder));
        }
    }

    public sealed class TestConfiguration : DbConfiguration
    {
        public TestConfiguration()
        {
            SetProviderFactory("System.Data.SQLite", SQLiteFactory.Instance);
            SetProviderFactory("System.Data.SQLite.EF6", SQLiteProviderFactory.Instance);
            SetProviderServices("System.Data.SQLite", (DbProviderServices) SQLiteProviderFactory.Instance.GetService(typeof(DbProviderServices)));
        }
    }
}
#endif
