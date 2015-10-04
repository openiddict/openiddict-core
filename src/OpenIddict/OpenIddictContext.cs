using System;
using Microsoft.AspNet.Identity.EntityFramework;
using Microsoft.Data.Entity;
using OpenIddict.Models;

namespace OpenIddict {
    public class OpenIddictContext<TUser, TRole, TKey> : IdentityDbContext<TUser, TRole, TKey>
        where TUser : IdentityUser<TKey>
        where TRole : IdentityRole<TKey>
        where TKey : IEquatable<TKey> {
        public DbSet<Application> Applications { get; set; }
    }

    public class OpenIddictContext<TUser> : OpenIddictContext<TUser, IdentityRole, string> where TUser : IdentityUser { }
}