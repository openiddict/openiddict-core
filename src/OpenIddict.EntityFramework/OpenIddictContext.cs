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
    public class OpenIddictContext : OpenIddictContext<OpenIddictUser> {
        /// <summary>
        /// Initializes a new OpenIddict context without configuring the Entity Framework options.
        /// </summary>
        protected OpenIddictContext() { }

        /// <summary>
        /// Initializes a new OpenIddict context.
        /// </summary>
        /// <param name="options">The options used to configure the Entity Framework context.</param>
        public OpenIddictContext(DbContextOptions options) : base(options) { }
    }

    /// <summary>
    /// Represents an OpenIddict-powered Entity Framework context.
    /// </summary>
    /// <typeparam name="TUser">The type of the User entity.</typeparam>
    public class OpenIddictContext<TUser> : OpenIddictContext<TUser, IdentityRole, OpenIddictApplication,
                                                                                   OpenIddictAuthorization,
                                                                                   OpenIddictScope,
                                                                                   OpenIddictToken, string>
        where TUser : OpenIddictUser {
        /// <summary>
        /// Initializes a new OpenIddict context without configuring the Entity Framework options.
        /// </summary>
        protected OpenIddictContext() { }

        /// <summary>
        /// Initializes a new OpenIddict context.
        /// </summary>
        /// <param name="options">The options used to configure the Entity Framework context.</param>
        public OpenIddictContext(DbContextOptions options) : base(options) { }
    }

    /// <summary>
    /// Represents an OpenIddict-powered Entity Framework context.
    /// </summary>
    /// <typeparam name="TUser">The type of the User entity.</typeparam>
    /// <typeparam name="TKey">The type of the primary key used by the Identity/OpenIddict entities.</typeparam>
    public class OpenIddictContext<TUser, TKey> : OpenIddictContext<TUser, IdentityRole<TKey>, OpenIddictApplication<TKey>,
                                                                                               OpenIddictAuthorization<TKey>,
                                                                                               OpenIddictScope<TKey>,
                                                                                               OpenIddictToken<TKey>, TKey>
        where TUser : OpenIddictUser<TKey>
        where TKey : IEquatable<TKey> {
        /// <summary>
        /// Initializes a new OpenIddict context without configuring the Entity Framework options.
        /// </summary>
        protected OpenIddictContext() { }

        /// <summary>
        /// Initializes a new OpenIddict context.
        /// </summary>
        /// <param name="options">The options used to configure the Entity Framework context.</param>
        public OpenIddictContext(DbContextOptions options) : base(options) { }
    }

    /// <summary>
    /// Represents an OpenIddict-powered Entity Framework context.
    /// </summary>
    /// <typeparam name="TUser">The type of the User entity.</typeparam>
    /// <typeparam name="TRole">The type of the Role entity.</typeparam>
    /// <typeparam name="TKey">The type of the primary key used by the Identity/OpenIddict entities.</typeparam>
    public class OpenIddictContext<TUser, TRole, TKey> : OpenIddictContext<TUser, TRole, OpenIddictApplication<TKey>,
                                                                                         OpenIddictAuthorization<TKey>,
                                                                                         OpenIddictScope<TKey>,
                                                                                         OpenIddictToken<TKey>, TKey>
        where TUser : OpenIddictUser<TKey>
        where TRole : IdentityRole<TKey>
        where TKey : IEquatable<TKey> {
        /// <summary>
        /// Initializes a new OpenIddict context without configuring the Entity Framework options.
        /// </summary>
        protected OpenIddictContext() { }

        /// <summary>
        /// Initializes a new OpenIddict context.
        /// </summary>
        /// <param name="options">The options used to configure the Entity Framework context.</param>
        public OpenIddictContext(DbContextOptions options) : base(options) { }
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
    public class OpenIddictContext<TUser, TRole, TApplication, TAuthorization, TScope, TToken, TKey> : IdentityDbContext<TUser, TRole, TKey>
        where TUser : OpenIddictUser<TKey, TAuthorization, TToken>
        where TRole : IdentityRole<TKey>
        where TApplication : OpenIddictApplication<TKey>
        where TAuthorization : OpenIddictAuthorization<TKey, TToken>
        where TScope : OpenIddictScope<TKey>
        where TToken : OpenIddictToken<TKey>
        where TKey : IEquatable<TKey> {
        /// <summary>
        /// Initializes a new OpenIddict context without configuring the Entity Framework options.
        /// </summary>
        protected OpenIddictContext() { }

        /// <summary>
        /// Initializes a new OpenIddict context.
        /// </summary>
        /// <param name="options">The options used to configure the Entity Framework context.</param>
        public OpenIddictContext(DbContextOptions options) : base(options) { }

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

            // Warning: optional foreign keys MUST NOT be added as CLR properties because
            // Entity Framework would throw an exception due to the TKey generic parameter
            // being non-nullable when using value types like short, int, long or Guid.

            // Configure the TApplication entity.
            builder.Entity<TApplication>(entity => {
                entity.HasKey(application => application.Id);

                entity.ToTable("OpenIddictApplications");
            });

            // Configure the TAuthorization entity.
            builder.Entity<TAuthorization>(entity => {
                entity.HasKey(authorization => authorization.Id);

                entity.HasMany(authorization => authorization.Tokens)
                      .WithOne()
                      .HasForeignKey("AuthorizationId")
                      .IsRequired(required: false);

                entity.ToTable("OpenIddictAuthorizations");
            });

            // Configure the TScope entity.
            builder.Entity<TScope>(entity => {
                entity.HasKey(scope => scope.Id);

                entity.ToTable("OpenIddictScopes");
            });

            // Configure the TToken entity.
            builder.Entity<TToken>(entity => {
                entity.HasKey(token => token.Id);

                entity.ToTable("OpenIddictTokens");
            });

            // Configure the TUser entity.
            builder.Entity<TUser>(entity => {
                entity.HasMany(user => user.Authorizations)
                      .WithOne()
                      .HasForeignKey("UserId")
                      .IsRequired(required: false);

                entity.HasMany(user => user.Tokens)
                      .WithOne()
                      .HasForeignKey("UserId")
                      .IsRequired(required: false);
            });
        }
    }
}