/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using Microsoft.AspNet.Identity.EntityFramework;
using Microsoft.Data.Entity;
using Microsoft.Data.Entity.Infrastructure;
using OpenIddict.Models;

namespace OpenIddict {
    public class OpenIddictContext<TUser, TApplication, TRole, TKey> : IdentityDbContext<TUser, TRole, TKey>
        where TUser : IdentityUser<TKey>
        where TApplication : Application
        where TRole : IdentityRole<TKey>
        where TKey : IEquatable<TKey> {
        public DbSet<TApplication> Applications { get; set; }

        public OpenIddictContext() {}
        public OpenIddictContext(DbContextOptions options) : base(options) {}
        public OpenIddictContext(IServiceProvider serviceProvider) : base(serviceProvider) {}
        public OpenIddictContext(IServiceProvider serviceProvider, DbContextOptions options) : base(serviceProvider, options) {}
    }

    public class OpenIddictContext<TUser> : OpenIddictContext<TUser, Application, IdentityRole, string> where TUser : IdentityUser {
        public OpenIddictContext() { }
        public OpenIddictContext(DbContextOptions options) : base(options) { }
        public OpenIddictContext(IServiceProvider serviceProvider) : base(serviceProvider) { }
        public OpenIddictContext(IServiceProvider serviceProvider, DbContextOptions options) : base(serviceProvider, options) { }
    }

    public class OpenIddictContext : OpenIddictContext<IdentityUser> {
        public OpenIddictContext() { }
        public OpenIddictContext(DbContextOptions options) : base(options) { }
        public OpenIddictContext(IServiceProvider serviceProvider) : base(serviceProvider) { }
        public OpenIddictContext(IServiceProvider serviceProvider, DbContextOptions options) : base(serviceProvider, options) { }
    }
}