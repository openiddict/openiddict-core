/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace OpenIddict {
    /// <summary>
    /// Represents an OpenIddict-powered Entity Framework context.
    /// </summary>
    public class OpenIddictDbContext : OpenIddictDbContext<OpenIddictUser> {
        /// <summary>
        /// Initializes a new OpenIddict context without configuring the Entity Framework options.
        /// </summary>
        protected OpenIddictDbContext() { }

        /// <summary>
        /// Initializes a new OpenIddict context.
        /// </summary>
        /// <param name="options">The options used to configure the Entity Framework context.</param>
        public OpenIddictDbContext(DbContextOptions options) : base(options) { }
    }

    /// <summary>
    /// Represents an OpenIddict-powered Entity Framework context.
    /// </summary>
    /// <typeparam name="TUser">The type of the User entity.</typeparam>
    public class OpenIddictDbContext<TUser> : OpenIddictDbContext<TUser, IdentityRole, OpenIddictApplication,
                                                                                       OpenIddictAuthorization,
                                                                                       OpenIddictScope,
                                                                                       OpenIddictToken, string>
        where TUser : OpenIddictUser {
        /// <summary>
        /// Initializes a new OpenIddict context without configuring the Entity Framework options.
        /// </summary>
        protected OpenIddictDbContext() { }

        /// <summary>
        /// Initializes a new OpenIddict context.
        /// </summary>
        /// <param name="options">The options used to configure the Entity Framework context.</param>
        public OpenIddictDbContext(DbContextOptions options) : base(options) { }
    }

    /// <summary>
    /// Represents an OpenIddict-powered Entity Framework context.
    /// </summary>
    /// <typeparam name="TUser">The type of the User entity.</typeparam>
    /// <typeparam name="TRole">The type of the Role entity.</typeparam>
    public class OpenIddictDbContext<TUser, TRole> : OpenIddictDbContext<TUser, TRole, OpenIddictApplication,
                                                                                       OpenIddictAuthorization,
                                                                                       OpenIddictScope,
                                                                                       OpenIddictToken, string>
        where TUser : OpenIddictUser
        where TRole : IdentityRole {
        /// <summary>
        /// Initializes a new OpenIddict context without configuring the Entity Framework options.
        /// </summary>
        protected OpenIddictDbContext() { }

        /// <summary>
        /// Initializes a new OpenIddict context.
        /// </summary>
        /// <param name="options">The options used to configure the Entity Framework context.</param>
        public OpenIddictDbContext(DbContextOptions options) : base(options) { }
    }

    /// <summary>
    /// Represents an OpenIddict-powered Entity Framework context.
    /// </summary>
    /// <typeparam name="TUser">The type of the User entity.</typeparam>
    /// <typeparam name="TRole">The type of the Role entity.</typeparam>
    /// <typeparam name="TKey">The type of the primary key used by the Identity/OpenIddict entities.</typeparam>
    public class OpenIddictDbContext<TUser, TRole, TKey> : OpenIddictDbContext<TUser, TRole, OpenIddictApplication<TKey>,
                                                                                             OpenIddictAuthorization<TKey>,
                                                                                             OpenIddictScope<TKey>,
                                                                                             OpenIddictToken<TKey>, TKey>
        where TUser : OpenIddictUser<TKey>
        where TRole : IdentityRole<TKey>
        where TKey : IEquatable<TKey> {
        /// <summary>
        /// Initializes a new OpenIddict context without configuring the Entity Framework options.
        /// </summary>
        protected OpenIddictDbContext() { }

        /// <summary>
        /// Initializes a new OpenIddict context.
        /// </summary>
        /// <param name="options">The options used to configure the Entity Framework context.</param>
        public OpenIddictDbContext(DbContextOptions options) : base(options) { }
    }

    /// <summary>
    /// Represents an OpenIddict-powered Entity Framework context.
    /// </summary>
    /// <typeparam name="TUser">The type of the User entity.</typeparam>
    /// <typeparam name="TRole">The type of the Role entity.</typeparam>
    /// <typeparam name="TApplication">The type of the Application entity.</typeparam>
    /// <typeparam name="TAuthorization">The type of the Authorization entity.</typeparam>
    /// <typeparam name="TScope">The type of the Scope entity.</typeparam>
    /// <typeparam name="TToken">The type of the Token entity.</typeparam>
    /// <typeparam name="TKey">The type of the primary key used by the Identity/OpenIddict entities.</typeparam>
    public class OpenIddictDbContext<TUser, TRole, TApplication, TAuthorization, TScope, TToken, TKey> : IdentityDbContext<TUser, TRole, TKey>
        where TUser : OpenIddictUser<TKey, TAuthorization, TToken>
        where TRole : IdentityRole<TKey>
        where TApplication : OpenIddictApplication<TKey, TToken>
        where TAuthorization : OpenIddictAuthorization<TKey, TToken>
        where TScope : OpenIddictScope<TKey>
        where TToken : OpenIddictToken<TKey>
        where TKey : IEquatable<TKey> {
        /// <summary>
        /// Initializes a new OpenIddict context without configuring the Entity Framework options.
        /// </summary>
        protected OpenIddictDbContext() { }

        /// <summary>
        /// Initializes a new OpenIddict context.
        /// </summary>
        /// <param name="options">The options used to configure the Entity Framework context.</param>
        public OpenIddictDbContext(DbContextOptions options) : base(options) { }

        /// <summary>
        /// Gets or sets the database set containing the applications.
        /// </summary>
        public DbSet<TApplication> Applications { get; set; }

        /// <summary>
        /// Gets or sets the database set containing the authorizations.
        /// </summary>
        public DbSet<TAuthorization> Authorizations { get; set; }

        /// <summary>
        /// Gets or sets the database set containing the scopes.
        /// </summary>
        public DbSet<TScope> Scopes { get; set; }

        /// <summary>
        /// Gets or sets the database set containing the tokens.
        /// </summary>
        public DbSet<TToken> Tokens { get; set; }

        /// <summary>
        /// Registers the OpenIddict entities in the Entity Framework context.
        /// </summary>
        /// <param name="builder">The model builder used by Entity Framework.</param>
        protected override void OnModelCreating(ModelBuilder builder) {
            base.OnModelCreating(builder);

            // Rename Identity tables.
            builder.Entity<TUser>(e => e.ToTable("OpenIddictUsers"));
            builder.Entity<TRole>(e => e.ToTable("OpenIddictRoles"));
            builder.Entity<IdentityUserClaim<TKey>>(e => e.ToTable("OpenIddictUserClaims"));
            builder.Entity<IdentityRoleClaim<TKey>>(e => e.ToTable("OpenIddictRoleClaims"));
            builder.Entity<IdentityUserRole<TKey>>(e => e.ToTable("OpenIddictUserRoles"));
            builder.Entity<IdentityUserLogin<TKey>>(e => e.ToTable("OpenIddictUserLogins"));
            builder.Entity<IdentityUserToken<TKey>>(e => e.ToTable("OpenIddictUserTokens"));

            // Warning: optional foreign keys MUST NOT be added as CLR properties because
            // Entity Framework would throw an exception due to the TKey generic parameter
            // being non-nullable when using value types like short, int, long or Guid.

            // Configure the TApplication entity.
            builder.Entity<TApplication>(e => {
                e.HasKey(app => app.Id);

                e.HasAlternateKey(app => app.ClientId);
                e.HasIndex(app => app.ClientId).HasName("ApplicationClientIdIndex");

                e.HasMany(app => app.Tokens)
                 .WithOne()
                 .HasForeignKey("ApplicationId")
                 .IsRequired(false);

                e.ToTable("OpenIddictApplications");

                e.Property(app => app.ClientId).IsRequired();
                e.Property(app => app.RedirectUri).IsRequired();
                e.Property(app => app.Type).IsRequired();
            });

            // Configure the TAuthorization entity.
            builder.Entity<TAuthorization>(e => {
                e.HasKey(auth => auth.Id);

                e.HasMany(auth => auth.Tokens)
                 .WithOne()
                 .HasForeignKey("AuthorizationId")
                 .IsRequired(false);

                e.ToTable("OpenIddictAuthorizations");
            });

            // Configure the TScope entity.
            builder.Entity<TScope>(e => {
                e.HasKey(scope => scope.Id);

                e.ToTable("OpenIddictScopes");
            });

            // Configure the TToken entity.
            builder.Entity<TToken>(e => {
                e.HasKey(token => token.Id);

                e.ToTable("OpenIddictTokens");

                e.Property(token => token.Type).IsRequired();
            });

            // Configure the TUser entity.
            builder.Entity<TUser>(e => {
                e.HasMany(user => user.Authorizations)
                 .WithOne()
                 .HasForeignKey("UserId")
                 .IsRequired(false);

                e.HasMany(user => user.Tokens)
                 .WithOne()
                 .HasForeignKey("UserId")
                 .IsRequired(false);
            });
        }
    }
}
