/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using Microsoft.AspNet.Identity.EntityFramework;
using Microsoft.Data.Entity;
using OpenIddict.Models;

namespace OpenIddict {
    public class OpenIddictContext<TUser, TApplication, TRole, TKey, TScope> : IdentityDbContext<TUser, TRole, TKey>
        where TUser : IdentityUser<TKey>
        where TApplication : Application
        where TRole : IdentityRole<TKey>
        where TKey : IEquatable<TKey>
        where TScope : Scope {
        public DbSet<TApplication> Applications { get; set; }
        public DbSet<TScope> Scopes { get; set; }
    }

    public class OpenIddictContext<TUser> : OpenIddictContext<TUser, Application, IdentityRole, string, Scope> where TUser : IdentityUser {
    }

    public class OpenIddictContext : OpenIddictContext<IdentityUser> {
    }
}