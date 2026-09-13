using System.Globalization;
using System.Security.Claims;
using Company.Server.Helpers;
using Company.Server.ViewModels;
using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.Abstractions;
using OpenIddict.Server.AspNetCore;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace Company.Server.Controllers;

public class AuthorizationController(
    IOpenIddictApplicationManager applicationManager,
    IOpenIddictAuthorizationManager authorizationManager,
    IOpenIddictScopeManager scopeManager,
    SignInManager<IdentityUser> signInManager,
    UserManager<IdentityUser> userManager) : Controller
{
    private const string IgnoreAuthenticationChallenge = "IgnoreAuthenticationChallenge";

    [HttpGet("~/connect/authorize")]
    [HttpPost("~/connect/authorize")]
    [IgnoreAntiforgeryToken]
    public async Task<IActionResult> Authorize()
    {
        // Note: the request contains the parameters sent to the authorization endpoint (or to the pushed
        // authorization endpoint) and MUST NOT be returned unprotected to the user agent.
        var request = HttpContext.GetOpenIddictServerRequest() ??
            throw new InvalidOperationException("The OpenID Connect request cannot be retrieved.");

        // Retrieve the user principal stored in the authentication cookie and redirect the user agent
        // to the login page if it can't be extracted, if prompt=login was specified, or if max_age
        // was specified and the authentication cookie is not considered "fresh" enough.
        var result = await HttpContext.AuthenticateAsync(IdentityConstants.ApplicationScheme);
        if (result is not { Succeeded: true } ||
            ((request.HasPromptValue(PromptValues.Login) || request.MaxAge is 0 ||
             (request.MaxAge is not null && result.Properties?.IssuedUtc is not null &&
              TimeProvider.System.GetUtcNow() - result.Properties.IssuedUtc > TimeSpan.FromSeconds(request.MaxAge.Value))) &&
            TempData[IgnoreAuthenticationChallenge] is null or false))
        {
            // If the client application requested promptless authentication,
            // return an error indicating that the user is not logged in.
            if (request.HasPromptValue(PromptValues.None))
            {
                return Forbid(Errors.LoginRequired, "The user is not logged in.");
            }

            // To avoid endless login -> authorization redirects, a temp data entry
            // is used to skip the challenge if the user has just been redirected.
            TempData[IgnoreAuthenticationChallenge] = true;

            return Challenge(new AuthenticationProperties
            {
                RedirectUri = Request.PathBase + Request.Path + QueryString.Create(
                    Request.HasFormContentType ? Request.Form : Request.Query)
            }, IdentityConstants.ApplicationScheme);
        }

        var user = await userManager.GetUserAsync(result.Principal);
        if (user is null)
        {
            return Challenge(new AuthenticationProperties
            {
                RedirectUri = Request.PathBase + Request.Path + QueryString.Create(
                    Request.HasFormContentType ? Request.Form : Request.Query)
            }, IdentityConstants.ApplicationScheme);
        }

        var application = await applicationManager.FindByClientIdAsync(request.ClientId!) ??
            throw new InvalidOperationException("Details concerning the calling client application cannot be found.");

        // Retrieve the permanent authorizations associated with the user and the calling client application.
        var authorizations = await authorizationManager.FindAsync(
            query: (
                Subject       : await userManager.GetUserIdAsync(user),
                ApplicationId : await applicationManager.GetIdAsync(application),
                Status        : Statuses.Valid,
                Type          : AuthorizationTypes.Permanent,
                RequiredScopes: request.GetScopes())).ToListAsync();

        switch (await applicationManager.GetConsentTypeAsync(application))
        {
            // If the consent is external (e.g when authorizations are granted by an administrator),
            // immediately return an error if no authorization can be found in the database.
            case ConsentTypes.External when authorizations.Count is 0:
                return Forbid(Errors.ConsentRequired, "The logged in user is not allowed to access this client application.");

            // If the consent is implicit or if an authorization was found,
            // return an authorization response without displaying the consent form.
            case ConsentTypes.Implicit:
            case ConsentTypes.External when authorizations.Count is not 0:
            case ConsentTypes.Explicit when authorizations.Count is not 0 && !request.HasPromptValue(PromptValues.Consent):
                return await SignInAsync(user, application, authorizations.LastOrDefault(), request.GetScopes());

            // At this point, no authorization was found in the database and an error must be returned
            // if the client application specified prompt=none in the authorization request.
            case ConsentTypes.Explicit   when request.HasPromptValue(PromptValues.None):
            case ConsentTypes.Systematic when request.HasPromptValue(PromptValues.None):
                return Forbid(Errors.ConsentRequired, "Interactive user consent is required.");

            // In every other case, render the consent form.
            default: return View(new AuthorizeViewModel
            {
                ApplicationName = await applicationManager.GetLocalizedDisplayNameAsync(application, CultureInfo.CurrentCulture),
                Scope = request.Scope
            });
        }
    }

    [Authorize, FormValueRequired("submit.Accept")]
    [HttpPost("~/connect/authorize"), ValidateAntiForgeryToken]
    public async Task<IActionResult> Accept()
    {
        var request = HttpContext.GetOpenIddictServerRequest() ??
            throw new InvalidOperationException("The OpenID Connect request cannot be retrieved.");

        var user = await userManager.GetUserAsync(User);
        if (user is null)
        {
            return Forbid(Errors.LoginRequired, "The account associated with the logged in user was removed.");
        }

        var application = await applicationManager.FindByClientIdAsync(request.ClientId!) ??
            throw new InvalidOperationException("Details concerning the calling client application cannot be found.");

        var authorizations = await authorizationManager.FindAsync(
            query: (
                Subject       : await userManager.GetUserIdAsync(user),
                ApplicationId : await applicationManager.GetIdAsync(application),
                Status        : Statuses.Valid,
                Type          : AuthorizationTypes.Permanent,
                RequiredScopes: request.GetScopes())).ToListAsync();

        // Note: the same check is already made in the other action but is repeated here to ensure
        // this POST-only endpoint can't be abused to bypass the external authorization requirement.
        if (authorizations.Count is 0 && await applicationManager.HasConsentTypeAsync(application, ConsentTypes.External))
        {
            return Forbid(Errors.ConsentRequired, "The logged in user is not allowed to access this client application.");
        }

        return await SignInAsync(user, application, authorizations.LastOrDefault(), request.GetScopes());
    }

    [Authorize, FormValueRequired("submit.Deny")]
    [HttpPost("~/connect/authorize"), ValidateAntiForgeryToken]
    // Notify OpenIddict that the authorization grant has been denied by the resource owner.
    public IActionResult Deny() => Forbid(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);

    [Authorize, HttpGet("~/connect/verify"), IgnoreAntiforgeryToken]
    public async Task<IActionResult> Verify()
    {
        // Retrieve the claims principal associated with the user code.
        var result = await HttpContext.AuthenticateAsync(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
        if (result is { Succeeded: true } && !string.IsNullOrEmpty(result.Principal.GetClaim(Claims.ClientId)))
        {
            var application = await applicationManager.FindByClientIdAsync(result.Principal.GetClaim(Claims.ClientId)!) ??
                throw new InvalidOperationException("Details concerning the calling client application cannot be found.");

            return View(new VerifyViewModel
            {
                ApplicationName = await applicationManager.GetLocalizedDisplayNameAsync(application, CultureInfo.CurrentCulture),
                Scope = string.Join(' ', result.Principal.GetScopes()),
                UserCode = result.Properties.GetTokenValue(OpenIddictServerAspNetCoreConstants.Tokens.UserCode)
            });
        }

        if (!string.IsNullOrEmpty(result.Properties?.GetTokenValue(OpenIddictServerAspNetCoreConstants.Tokens.UserCode)))
        {
            return View(new VerifyViewModel
            {
                Error = Errors.InvalidToken,
                ErrorDescription = "The specified user code is not valid. Please make sure you typed it correctly."
            });
        }

        // Otherwise, render a form asking the user to enter the user code manually.
        return View(new VerifyViewModel());
    }

    [Authorize, FormValueRequired("submit.Accept")]
    [HttpPost("~/connect/verify"), ValidateAntiForgeryToken]
    public async Task<IActionResult> VerifyAccept()
    {
        var user = await userManager.GetUserAsync(User);
        if (user is null)
        {
            return Forbid(Errors.LoginRequired, "The account associated with the logged in user was removed.");
        }

        var result = await HttpContext.AuthenticateAsync(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
        if (result is { Succeeded: true } && !string.IsNullOrEmpty(result.Principal.GetClaim(Claims.ClientId)))
        {
            var identity = await CreateIdentityAsync(user, result.Principal.GetScopes());

            // The redirect URI is the address the user is redirected to after the demand is validated.
            return SignIn(new ClaimsPrincipal(identity), new AuthenticationProperties { RedirectUri = "/" },
                OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
        }

        return View(new VerifyViewModel
        {
            Error = Errors.InvalidToken,
            ErrorDescription = "The specified user code is not valid. Please make sure you typed it correctly."
        });
    }

    [Authorize, FormValueRequired("submit.Deny")]
    [HttpPost("~/connect/verify"), ValidateAntiForgeryToken]
    public IActionResult VerifyDeny() => Forbid(new AuthenticationProperties { RedirectUri = "/" },
        OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);

    [HttpGet("~/connect/endsession")]
    public IActionResult EndSession() => View();

    [ActionName(nameof(EndSession)), HttpPost("~/connect/endsession"), ValidateAntiForgeryToken]
    public async Task<IActionResult> EndSessionPost()
    {
        // Delete the local authentication cookie.
        await signInManager.SignOutAsync();

        // Ask OpenIddict to redirect the user agent to the post_logout_redirect_uri
        // specified by the client application or to the RedirectUri specified below.
        return SignOut(new AuthenticationProperties { RedirectUri = "/" },
            OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
    }

    [HttpPost("~/connect/token"), IgnoreAntiforgeryToken, Produces("application/json")]
    public async Task<IActionResult> Exchange()
    {
        var request = HttpContext.GetOpenIddictServerRequest() ??
            throw new InvalidOperationException("The OpenID Connect request cannot be retrieved.");

        if (request.IsAuthorizationCodeGrantType() || request.IsDeviceCodeGrantType() || request.IsRefreshTokenGrantType())
        {
            // Retrieve the claims principal stored in the authorization code/device code/refresh token.
            var result = await HttpContext.AuthenticateAsync(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);

            var user = await userManager.FindByIdAsync(result.Principal!.GetClaim(Claims.Subject)!);
            if (user is null)
            {
                return Forbid(Errors.InvalidGrant, "The token is no longer valid.");
            }

            // Ensure the user is still allowed to sign in.
            if (!await signInManager.CanSignInAsync(user))
            {
                return Forbid(Errors.InvalidGrant, "The user is no longer allowed to sign in.");
            }

            var identity = new ClaimsIdentity(result.Principal!.Claims,
                authenticationType: TokenValidationParameters.DefaultAuthenticationType,
                nameType: Claims.Name,
                roleType: Claims.Role);

            // Override the user claims present in the principal in case they changed since the token was issued.
            await SetUserClaimsAsync(identity, user);
            identity.SetDestinations(GetDestinations);

            return SignIn(new ClaimsPrincipal(identity), OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
        }

        if (request.IsClientCredentialsGrantType())
        {
            // Note: the client credentials are automatically validated by OpenIddict.
            var application = await applicationManager.FindByClientIdAsync(request.ClientId!) ??
                throw new InvalidOperationException("The application details cannot be found in the database.");

            var identity = new ClaimsIdentity(
                authenticationType: TokenValidationParameters.DefaultAuthenticationType,
                nameType: Claims.Name,
                roleType: Claims.Role);

            // Use the client_id as the subject identifier.
            identity.SetClaim(Claims.Subject, await applicationManager.GetClientIdAsync(application))
                    .SetClaim(Claims.Name, await applicationManager.GetDisplayNameAsync(application));

            identity.SetScopes(request.GetScopes());
            identity.SetResources(await scopeManager.ListResourcesAsync(identity.GetScopes()).ToListAsync());
            identity.SetDestinations(GetDestinations);

            return SignIn(new ClaimsPrincipal(identity), OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
        }

        throw new InvalidOperationException("The specified grant type is not supported.");
    }

    private async Task<IActionResult> SignInAsync(IdentityUser user, object application,
        object? authorization, IEnumerable<string> scopes)
    {
        var identity = await CreateIdentityAsync(user, scopes);

        // Automatically create a permanent authorization to avoid requiring explicit consent
        // for future authorization or token requests containing the same scopes.
        authorization ??= await authorizationManager.CreateAsync(new OpenIddictAuthorizationDescriptor
        {
            ApplicationId = await applicationManager.GetIdAsync(application),
            Principal = new ClaimsPrincipal(identity),
            Scopes = [.. identity.GetScopes()],
            Subject = await userManager.GetUserIdAsync(user),
            Type = AuthorizationTypes.Permanent
        });

        identity.SetAuthorizationId(await authorizationManager.GetIdAsync(authorization));

        return SignIn(new ClaimsPrincipal(identity), OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
    }

    private async Task<ClaimsIdentity> CreateIdentityAsync(IdentityUser user, IEnumerable<string> scopes)
    {
        // Create the claims-based identity that will be used by OpenIddict to generate tokens.
        var identity = new ClaimsIdentity(
            authenticationType: TokenValidationParameters.DefaultAuthenticationType,
            nameType: Claims.Name,
            roleType: Claims.Role);

        await SetUserClaimsAsync(identity, user);

        // Note: the granted scopes match the requested scopes but you may want to allow
        // the user to uncheck specific scopes: for that, restrict the list of scopes here.
        identity.SetScopes(scopes);
        identity.SetResources(await scopeManager.ListResourcesAsync(identity.GetScopes()).ToListAsync());
        identity.SetDestinations(GetDestinations);

        return identity;
    }

    private async Task SetUserClaimsAsync(ClaimsIdentity identity, IdentityUser user)
    {
        identity.SetClaim(Claims.Subject, await userManager.GetUserIdAsync(user))
                .SetClaim(Claims.Email, await userManager.GetEmailAsync(user))
                .SetClaim(Claims.Name, await userManager.GetUserNameAsync(user))
                .SetClaim(Claims.PreferredUsername, await userManager.GetUserNameAsync(user))
                .SetClaims(Claims.Role, [.. await userManager.GetRolesAsync(user)]);
    }

    private ForbidResult Forbid(string error, string description) => Forbid(
        authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
        properties: new AuthenticationProperties(new Dictionary<string, string?>
        {
            [OpenIddictServerAspNetCoreConstants.Properties.Error] = error,
            [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] = description
        }));

    private static IEnumerable<string> GetDestinations(Claim claim)
    {
        // Note: by default, claims are NOT automatically included in the access and identity tokens.
        // To allow OpenIddict to serialize them, a destination must be attached to each claim.
        switch (claim.Type)
        {
            case Claims.Name or Claims.PreferredUsername:
                yield return Destinations.AccessToken;

                if (claim.Subject!.HasScope(Scopes.Profile))
                    yield return Destinations.IdentityToken;

                yield break;

            case Claims.Email:
                yield return Destinations.AccessToken;

                if (claim.Subject!.HasScope(Scopes.Email))
                    yield return Destinations.IdentityToken;

                yield break;

            case Claims.Role:
                yield return Destinations.AccessToken;

                if (claim.Subject!.HasScope(Scopes.Roles))
                    yield return Destinations.IdentityToken;

                yield break;

            // Never include the security stamp in the access and identity tokens, as it's a secret value.
            case "AspNet.Identity.SecurityStamp": yield break;

            default:
                yield return Destinations.AccessToken;
                yield break;
        }
    }
}
