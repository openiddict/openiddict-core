#if NET
using Microsoft.EntityFrameworkCore;
#else
using System.Data.Entity;
using SQLite.CodeFirst;
#endif

namespace OpenIddict.Sandbox.WinForms.Client.Models;

public class ApplicationDbContext : DbContext
{
#if NET
    public ApplicationDbContext(DbContextOptions options)
        : base(options)
    {
    }

    protected override void OnModelCreating(ModelBuilder builder)
    {
        base.OnModelCreating(builder);

        builder.UseOpenIddict();
    }

    protected override void OnConfiguring(DbContextOptionsBuilder optionsBuilder)
    {
        optionsBuilder.UseSqlite($"Filename={Path.Combine(Path.GetTempPath(), "openiddict-sandbox-winforms-client.sqlite3")}");
    }
#else
    public ApplicationDbContext()
        : base("name=DefaultConnection")
    {
    }

    protected override void OnModelCreating(DbModelBuilder modelBuilder)
    {
        base.OnModelCreating(modelBuilder);

        modelBuilder.UseOpenIddict();

        // Override the default database initializer to use the one provided
        // by SQLite.CodeFirst, which automatically creates the database.
        Database.SetInitializer(new SqliteCreateDatabaseIfNotExists<ApplicationDbContext>(modelBuilder));
    }
#endif
}
