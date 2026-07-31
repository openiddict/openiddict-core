using System;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.EntityFramework;
using Microsoft.AspNet.Identity.Owin;
using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Cookies;
using OpenIddict.Abstractions;
using OpenIddict.Sandbox.AspNet.Server.Models;

namespace OpenIddict.Sandbox.AspNet.Server;

public class EmailService : IIdentityMessageService
{
    public Task SendAsync(IdentityMessage message) => Task.CompletedTask;
}

public class SmsService : IIdentityMessageService
{
    public Task SendAsync(IdentityMessage message) => Task.CompletedTask;
}

public class ApplicationUserManager : UserManager<ApplicationUser>
{
    public ApplicationUserManager(IUserStore<ApplicationUser> store)
        : base(store)
    {
    }

    public static ApplicationUserManager Create(IdentityFactoryOptions<ApplicationUserManager> options, IOwinContext context) 
    {
        var manager = new ApplicationUserManager(new UserStore<ApplicationUser>(context.Get<ApplicationDbContext>()));

        manager.UserValidator = new UserValidator<ApplicationUser>(manager)
        {
            AllowOnlyAlphanumericUserNames = false,
            RequireUniqueEmail = true
        };

        manager.PasswordValidator = new PasswordValidator
        {
            RequiredLength = 6,
            RequireNonLetterOrDigit = true,
            RequireDigit = true,
            RequireLowercase = true,
            RequireUppercase = true,
        };

        manager.UserLockoutEnabledByDefault = true;
        manager.DefaultAccountLockoutTimeSpan = TimeSpan.FromMinutes(5);
        manager.MaxFailedAccessAttemptsBeforeLockout = 5;

        manager.RegisterTwoFactorProvider("Code téléphonique ", new PhoneNumberTokenProvider<ApplicationUser>
        {
            MessageFormat = "Votre code de sécurité est {0}"
        });
        manager.RegisterTwoFactorProvider("Code d'e-mail", new EmailTokenProvider<ApplicationUser>
        {
            Subject = "Code de sécurité",
            BodyFormat = "Votre code de sécurité est {0}"
        });
        manager.EmailService = new EmailService();
        manager.SmsService = new SmsService();
        var dataProtectionProvider = options.DataProtectionProvider;
        if (dataProtectionProvider is not null)
        {
            manager.UserTokenProvider = 
                new DataProtectorTokenProvider<ApplicationUser>(dataProtectionProvider.Create("ASP.NET Identity"));
        }
        return manager;
    }
}

public class ApplicationSignInManager : SignInManager<ApplicationUser, string>
{
    public ApplicationSignInManager(ApplicationUserManager userManager, IAuthenticationManager authenticationManager)
        : base(userManager, authenticationManager)
    {
    }

    public override Task<ClaimsIdentity> CreateUserIdentityAsync(ApplicationUser user)
    {
        return user.GenerateUserIdentityAsync((ApplicationUserManager)UserManager);
    }

    public static ApplicationSignInManager Create(IdentityFactoryOptions<ApplicationSignInManager> options, IOwinContext context)
    {
        return new ApplicationSignInManager(context.GetUserManager<ApplicationUserManager>(), context.Authentication);
    }

    public static async Task OnValidateIdentity(CookieValidateIdentityContext context)
    {
        // Note: the logic implemented here is equivalent to the default security stamp validation logic used
        // by ASP.NET Identity but allows overriding the login identifier claim to ensure it is preserved
        // when the identity is regenerated and the new application cookie is returned to the user agent.
        //
        // Unlike the default implementation, this method also uses a time-constant comparison
        // to prevent leaking information about the security stamp value through timing attacks.

        if ((context.Options.SystemClock.UtcNow - context.Properties.IssuedUtc) < TimeSpan.FromMinutes(30))
        {
            return;
        }

        var manager = context.OwinContext.GetUserManager<ApplicationUserManager>()
            ?? throw new InvalidOperationException("The user manager cannot be resolved from the context.");

        if (!manager.SupportsUserSecurityStamp)
        {
            throw new InvalidOperationException("The user manager does not support security stamp-based validation.");
        }

        if (string.IsNullOrEmpty(context.Identity.GetUserId()))
        {
            throw new InvalidOperationException("The user ID cannot be resolved from the user identity.");
        }

        if (string.IsNullOrEmpty(context.Identity.FindFirstValue(Constants.DefaultSecurityStampClaimType)))
        {
            throw new InvalidOperationException("The security stamp cannot be resolved from the user identity.");
        }

        var user = await manager.FindByIdAsync(context.Identity.GetUserId());
        if (user is null || await manager.GetSecurityStampAsync(user.Id) is not { Length: > 0 } value)
        {
            context.RejectIdentity();
            context.OwinContext.Authentication.SignOut(context.Options.AuthenticationType);
            return;
        }

        if (!FixedTimeEquals(
            left : MemoryMarshal.AsBytes<char>(value),
            right: MemoryMarshal.AsBytes<char>(context.Identity.FindFirstValue(Constants.DefaultSecurityStampClaimType))))
        {
            context.RejectIdentity();
            context.OwinContext.Authentication.SignOut(context.Options.AuthenticationType);
            return;
        }

        if (await user.GenerateUserIdentityAsync(manager) is not ClaimsIdentity identity)
        {
            throw new InvalidOperationException("The user identity cannot be generated for the specified user.");
        }

        var identifier = context.Identity.GetClaim("login_id");
        if (!string.IsNullOrEmpty(identifier))
        {
            identity.SetClaim("login_id", identifier);
        }

        context.Properties.IssuedUtc = null;
        context.Properties.ExpiresUtc = null;
        context.OwinContext.Authentication.SignIn(context.Properties, identity);

        [MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.NoOptimization)]
        static bool FixedTimeEquals(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right)
        {
            // Note: the logic used here is directly taken from the official implementation of
            // the CryptographicOperations.FixedTimeEquals() method introduced in .NET Core 2.1.
            //
            // See https://github.com/dotnet/corefx/pull/27103 for more information.

            // Note: these null checks can be theoretically considered as early checks
            // (which would defeat the purpose of a time-constant comparison method),
            // but the expected string length is the only information an attacker
            // could get at this stage, which is not critical where this method is used.

            if (left.Length != right.Length)
            {
                return false;
            }

            var length = left.Length;
            var accumulator = 0;

            for (var index = 0; index < length; index++)
            {
                accumulator |= left[index] - right[index];
            }

            return accumulator is 0;
        }
    }
}
