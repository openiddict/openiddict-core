using System.Buffers.Text;
using System.Data.Entity;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Threading.Tasks;
using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.EntityFramework;

namespace OpenIddict.Sandbox.AspNet.Server.Models;

public class ApplicationUser : IdentityUser
{
    public async Task<ClaimsIdentity> GenerateUserIdentityAsync(UserManager<ApplicationUser> manager)
    {
        var identity = await manager.CreateIdentityAsync(this, DefaultAuthenticationTypes.ApplicationCookie);

        // Generate and attach a unique login identifier to the claims identity: this value will
        // be used by the authorization controller to infer a unique identifier representing the
        // current user session and bind the tokens issued by OpenIddict to a specific session.
        //
        // Note: this method is also called when the application cookie is refreshed: to ensure
        // the login identifier is preserved, a custom OnRefreshingPrincipal event handler is used
        // to copy the login identifier from the existing principal to the refreshed instance.
        identity.AddClaim(new Claim("login_id", Base64Url.EncodeToString(RandomNumberGenerator.GetBytes(256 / 8))));

        return identity;
    }
}

public class ApplicationDbContext : IdentityDbContext<ApplicationUser>
{
    public ApplicationDbContext()
        : base("DefaultConnection", throwIfV1Schema: false)
    {
    }

    public static ApplicationDbContext Create()
    {
        return new ApplicationDbContext();
    }

    protected override void OnModelCreating(DbModelBuilder modelBuilder)
    {
        base.OnModelCreating(modelBuilder);

        modelBuilder.UseOpenIddict();
    }
}