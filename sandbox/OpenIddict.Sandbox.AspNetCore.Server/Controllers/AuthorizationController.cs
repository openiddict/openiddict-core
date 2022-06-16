/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Collections.Immutable;
using System.Security.Claims;
using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Primitives;
using OpenIddict.Abstractions;
using OpenIddict.Client.AspNetCore;
using OpenIddict.Sandbox.AspNetCore.Server.Helpers;
using OpenIddict.Sandbox.AspNetCore.Server.Models;
using OpenIddict.Sandbox.AspNetCore.Server.ViewModels.Authorization;
using OpenIddict.Server.AspNetCore;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace OpenIddict.Sandbox.AspNetCore.Server;

public class AuthorizationController : Controller
{
    private readonly IOpenIddictApplicationManager _applicationManager;
    private readonly IOpenIddictAuthorizationManager _authorizationManager;
    private readonly IOpenIddictScopeManager _scopeManager;
    private readonly SignInManager<ApplicationUser> _signInManager;
    private readonly UserManager<ApplicationUser> _userManager;

    public AuthorizationController(
        IOpenIddictApplicationManager applicationManager,
        IOpenIddictAuthorizationManager authorizationManager,
        IOpenIddictScopeManager scopeManager,
        SignInManager<ApplicationUser> signInManager,
        UserManager<ApplicationUser> userManager)
    {
        _applicationManager = applicationManager;
        _authorizationManager = authorizationManager;
        _scopeManager = scopeManager;
        _signInManager = signInManager;
        _userManager = userManager;
    }

    #region Authorization code, implicit and hybrid flows
    // Note: to support interactive flows like the code flow,
    // you must provide your own authorization endpoint action:

    [HttpGet("~/connect/authorize")]
    [HttpPost("~/connect/authorize")]
    [IgnoreAntiforgeryToken]
    public async Task<IActionResult> Authorize()
    {
        var request = HttpContext.GetOpenIddictServerRequest() ??
            throw new InvalidOperationException("The OpenID Connect request cannot be retrieved.");

        // Try to retrieve the user principal stored in the authentication cookie and redirect
        // the user agent to the login page (or to an external provider) in the following cases:
        //
        //  - If the user principal can't be extracted or the cookie is too old.
        //  - If prompt=login was specified by the client application.
        //  - If a max_age parameter was provided and the authentication cookie is not considered "fresh" enough.
        var result = await HttpContext.AuthenticateAsync(IdentityConstants.ApplicationScheme);
        if (result == null || !result.Succeeded || request.HasPrompt(Prompts.Login) ||
           (request.MaxAge != null && result.Properties?.IssuedUtc != null &&
            DateTimeOffset.UtcNow - result.Properties.IssuedUtc > TimeSpan.FromSeconds(request.MaxAge.Value)))
        {
            // If the client application requested promptless authentication,
            // return an error indicating that the user is not logged in.
            if (request.HasPrompt(Prompts.None))
            {
                return Forbid(
                    authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
                    properties: new AuthenticationProperties(new Dictionary<string, string>
                    {
                        [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.LoginRequired,
                        [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] = "The user is not logged in."
                    }));
            }

            // To avoid endless login -> authorization redirects, the prompt=login flag
            // is removed from the authorization request payload before redirecting the user.
            var prompt = string.Join(" ", request.GetPrompts().Remove(Prompts.Login));

            var parameters = Request.HasFormContentType ?
                Request.Form.Where(parameter => parameter.Key != Parameters.Prompt).ToList() :
                Request.Query.Where(parameter => parameter.Key != Parameters.Prompt).ToList();

            parameters.Add(KeyValuePair.Create(Parameters.Prompt, new StringValues(prompt)));

            // For applications that want to allow the client to select the external authentication provider
            // that will be used to authenticate the user, the identity_provider parameter can be used for that.
            if (!string.IsNullOrEmpty(request.IdentityProvider))
            {
                var issuer = request.IdentityProvider switch
                {
                    "github" => "https://github.com/",

                    _ => null
                };

                if (string.IsNullOrEmpty(issuer))
                {
                    return Forbid(
                        authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
                        properties: new AuthenticationProperties(new Dictionary<string, string>
                        {
                            [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.InvalidRequest,
                            [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] =
                                "The specified identity provider is not valid."
                        }));
                }

                var properties = _signInManager.ConfigureExternalAuthenticationProperties(
                    provider: issuer,
                    redirectUrl: Url.Action("ExternalLoginCallback", "Account", new
                    {
                        ReturnUrl = Request.PathBase + Request.Path + QueryString.Create(parameters)
                    }));

                // Note: when only one client is registered in the client options,
                // setting the issuer property is not required and can be omitted.
                properties.SetString(OpenIddictClientAspNetCoreConstants.Properties.Issuer, issuer);

                // Ask the OpenIddict client middleware to redirect the user agent to the identity provider.
                return Challenge(properties, OpenIddictClientAspNetCoreDefaults.AuthenticationScheme);
            }

            return Challenge(
                authenticationSchemes: IdentityConstants.ApplicationScheme,
                properties: new AuthenticationProperties
                {
                    RedirectUri = Request.PathBase + Request.Path + QueryString.Create(parameters)
                });
        }

        // Retrieve the profile of the logged in user.
        var user = await _userManager.GetUserAsync(result.Principal) ??
            throw new InvalidOperationException("The user details cannot be retrieved.");

        // Retrieve the application details from the database.
        var application = await _applicationManager.FindByClientIdAsync(request.ClientId) ??
            throw new InvalidOperationException("Details concerning the calling client application cannot be found.");

        // Retrieve the permanent authorizations associated with the user and the calling client application.
        var authorizations = await _authorizationManager.FindAsync(
            subject: await _userManager.GetUserIdAsync(user),
            client : await _applicationManager.GetIdAsync(application),
            status : Statuses.Valid,
            type   : AuthorizationTypes.Permanent,
            scopes : request.GetScopes()).ToListAsync();

        switch (await _applicationManager.GetConsentTypeAsync(application))
        {
            // If the consent is external (e.g when authorizations are granted by a sysadmin),
            // immediately return an error if no authorization can be found in the database.
            case ConsentTypes.External when !authorizations.Any():
                return Forbid(
                    authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
                    properties: new AuthenticationProperties(new Dictionary<string, string>
                    {
                        [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.ConsentRequired,
                        [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] =
                            "The logged in user is not allowed to access this client application."
                    }));

            // If the consent is implicit or if an authorization was found,
            // return an authorization response without displaying the consent form.
            case ConsentTypes.Implicit:
            case ConsentTypes.External when authorizations.Any():
            case ConsentTypes.Explicit when authorizations.Any() && !request.HasPrompt(Prompts.Consent):
                // Create the claims-based identity that will be used by OpenIddict to generate tokens.
                var identity = new ClaimsIdentity(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme)
                    .AddClaim(Claims.Subject, await _userManager.GetUserIdAsync(user))
                    .AddClaim(Claims.Email, await _userManager.GetEmailAsync(user))
                    .AddClaim(Claims.Name, await _userManager.GetUserNameAsync(user))
                    .AddClaims(Claims.Role, (await _userManager.GetRolesAsync(user)).ToImmutableArray());

                // Note: in this sample, the granted scopes match the requested scope
                // but you may want to allow the user to uncheck specific scopes.
                // For that, simply restrict the list of scopes before calling SetScopes.
                identity.SetScopes(request.GetScopes());
                identity.SetResources(await _scopeManager.ListResourcesAsync(identity.GetScopes()).ToListAsync());

                // Automatically create a permanent authorization to avoid requiring explicit consent
                // for future authorization or token requests containing the same scopes.
                var authorization = authorizations.LastOrDefault();
                if (authorization is null)
                {
                    authorization = await _authorizationManager.CreateAsync(
                        principal: new ClaimsPrincipal(identity),
                        subject  : await _userManager.GetUserIdAsync(user),
                        client   : await _applicationManager.GetIdAsync(application),
                        type     : AuthorizationTypes.Permanent,
                        scopes   : identity.GetScopes());
                }

                identity.SetAuthorizationId(await _authorizationManager.GetIdAsync(authorization));
                identity.SetDestinations(GetDestinations);

                return SignIn(new ClaimsPrincipal(identity), OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);

            // At this point, no authorization was found in the database and an error must be returned
            // if the client application specified prompt=none in the authorization request.
            case ConsentTypes.Explicit   when request.HasPrompt(Prompts.None):
            case ConsentTypes.Systematic when request.HasPrompt(Prompts.None):
                return Forbid(
                    authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
                    properties: new AuthenticationProperties(new Dictionary<string, string>
                    {
                        [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.ConsentRequired,
                        [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] =
                            "Interactive user consent is required."
                    }));

            // In every other case, render the consent form.
            default: return View(new AuthorizeViewModel
            {
                ApplicationName = await _applicationManager.GetLocalizedDisplayNameAsync(application),
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

        // Retrieve the profile of the logged in user.
        var user = await _userManager.GetUserAsync(User) ??
            throw new InvalidOperationException("The user details cannot be retrieved.");

        // Retrieve the application details from the database.
        var application = await _applicationManager.FindByClientIdAsync(request.ClientId) ??
            throw new InvalidOperationException("Details concerning the calling client application cannot be found.");

        // Retrieve the permanent authorizations associated with the user and the calling client application.
        var authorizations = await _authorizationManager.FindAsync(
            subject: await _userManager.GetUserIdAsync(user),
            client : await _applicationManager.GetIdAsync(application),
            status : Statuses.Valid,
            type   : AuthorizationTypes.Permanent,
            scopes : request.GetScopes()).ToListAsync();

        // Note: the same check is already made in the other action but is repeated
        // here to ensure a malicious user can't abuse this POST-only endpoint and
        // force it to return a valid response without the external authorization.
        if (!authorizations.Any() && await _applicationManager.HasConsentTypeAsync(application, ConsentTypes.External))
        {
            return Forbid(
                authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
                properties: new AuthenticationProperties(new Dictionary<string, string>
                {
                    [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.ConsentRequired,
                    [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] =
                        "The logged in user is not allowed to access this client application."
                }));
        }

        // Create the claims-based identity that will be used by OpenIddict to generate tokens.
        var identity = new ClaimsIdentity(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme)
            .AddClaim(Claims.Subject, await _userManager.GetUserIdAsync(user))
            .AddClaim(Claims.Email, await _userManager.GetEmailAsync(user))
            .AddClaim(Claims.Name, await _userManager.GetUserNameAsync(user))
            .AddClaims(Claims.Role, (await _userManager.GetRolesAsync(user)).ToImmutableArray());

        // Note: in this sample, the granted scopes match the requested scope
        // but you may want to allow the user to uncheck specific scopes.
        // For that, simply restrict the list of scopes before calling SetScopes.
        identity.SetScopes(request.GetScopes());
        identity.SetResources(await _scopeManager.ListResourcesAsync(identity.GetScopes()).ToListAsync());

        // Automatically create a permanent authorization to avoid requiring explicit consent
        // for future authorization or token requests containing the same scopes.
        var authorization = authorizations.LastOrDefault();
        if (authorization is null)
        {
            authorization = await _authorizationManager.CreateAsync(
                principal: new ClaimsPrincipal(identity),
                subject  : await _userManager.GetUserIdAsync(user),
                client   : await _applicationManager.GetIdAsync(application),
                type     : AuthorizationTypes.Permanent,
                scopes   : identity.GetScopes());
        }

        identity.SetAuthorizationId(await _authorizationManager.GetIdAsync(authorization));
        identity.SetDestinations(GetDestinations);

        // Returning a SignInResult will ask OpenIddict to issue the appropriate access/identity tokens.
        return SignIn(new ClaimsPrincipal(identity), OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
    }

    [Authorize, FormValueRequired("submit.Deny")]
    [HttpPost("~/connect/authorize"), ValidateAntiForgeryToken]
    // Notify OpenIddict that the authorization grant has been denied by the resource owner
    // to redirect the user agent to the client application using the appropriate response_mode.
    public IActionResult Deny() => Forbid(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
    #endregion

    #region Device flow
    // Note: to support the device flow, you must provide your own verification endpoint action:
    [Authorize, HttpGet("~/connect/verify")]
    public async Task<IActionResult> Verify()
    {
        var request = HttpContext.GetOpenIddictServerRequest() ??
            throw new InvalidOperationException("The OpenID Connect request cannot be retrieved.");

        // If the user code was not specified in the query string (e.g as part of the verification_uri_complete),
        // render a form to ask the user to enter the user code manually (non-digit chars are automatically ignored).
        if (string.IsNullOrEmpty(request.UserCode))
        {
            return View(new VerifyViewModel());
        }

        // Retrieve the claims principal associated with the user code.
        var result = await HttpContext.AuthenticateAsync(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
        if (result.Succeeded)
        {
            // Retrieve the application details from the database using the client_id stored in the principal.
            var application = await _applicationManager.FindByClientIdAsync(result.Principal.GetClaim(Claims.ClientId)) ??
                throw new InvalidOperationException("Details concerning the calling client application cannot be found.");

            // Render a form asking the user to confirm the authorization demand.
            return View(new VerifyViewModel
            {
                ApplicationName = await _applicationManager.GetLocalizedDisplayNameAsync(application),
                Scope = string.Join(" ", result.Principal.GetScopes()),
                UserCode = request.UserCode
            });
        }

        // Redisplay the form when the user code is not valid.
        return View(new VerifyViewModel
        {
            Error = Errors.InvalidToken,
            ErrorDescription = "The specified user code is not valid. Please make sure you typed it correctly."
        });
    }

    [Authorize, FormValueRequired("submit.Accept")]
    [HttpPost("~/connect/verify"), ValidateAntiForgeryToken]
    public async Task<IActionResult> VerifyAccept()
    {
        // Retrieve the profile of the logged in user.
        var user = await _userManager.GetUserAsync(User) ??
            throw new InvalidOperationException("The user details cannot be retrieved.");

        // Retrieve the claims principal associated with the user code.
        var result = await HttpContext.AuthenticateAsync(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
        if (result.Succeeded)
        {
            // Create the claims-based identity that will be used by OpenIddict to generate tokens.
            var identity = new ClaimsIdentity(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme)
                .AddClaim(Claims.Subject, await _userManager.GetUserIdAsync(user))
                .AddClaim(Claims.Email, await _userManager.GetEmailAsync(user))
                .AddClaim(Claims.Name, await _userManager.GetUserNameAsync(user))
                .AddClaims(Claims.Role, (await _userManager.GetRolesAsync(user)).ToImmutableArray());

            // Note: in this sample, the granted scopes match the requested scope
            // but you may want to allow the user to uncheck specific scopes.
            // For that, simply restrict the list of scopes before calling SetScopes.
            identity.SetScopes(result.Principal.GetScopes());
            identity.SetResources(await _scopeManager.ListResourcesAsync(identity.GetScopes()).ToListAsync());
            identity.SetDestinations(GetDestinations);

            var properties = new AuthenticationProperties
            {
                // This property points to the address OpenIddict will automatically
                // redirect the user to after validating the authorization demand.
                RedirectUri = "/"
            };

            return SignIn(new ClaimsPrincipal(identity), properties, OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
        }

        // Redisplay the form when the user code is not valid.
        return View(new VerifyViewModel
        {
            Error = Errors.InvalidToken,
            ErrorDescription = "The specified user code is not valid. Please make sure you typed it correctly."
        });
    }

    [Authorize, FormValueRequired("submit.Deny")]
    [HttpPost("~/connect/verify"), ValidateAntiForgeryToken]
    // Notify OpenIddict that the authorization grant has been denied by the resource owner.
    public IActionResult VerifyDeny() => Forbid(
        authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
        properties: new AuthenticationProperties()
        {
            // This property points to the address OpenIddict will automatically
            // redirect the user to after rejecting the authorization demand.
            RedirectUri = "/"
        });
    #endregion

    #region Logout support for interactive flows like code and implicit
    // Note: the logout action is only useful when implementing interactive
    // flows like the authorization code flow or the implicit flow.

    [HttpGet("~/connect/logout")]
    public IActionResult Logout() => View();

    [ActionName(nameof(Logout)), HttpPost("~/connect/logout"), ValidateAntiForgeryToken]
    public async Task<IActionResult> LogoutPost()
    {
        // Ask ASP.NET Core Identity to delete the local and external cookies created
        // when the user agent is redirected from the external identity provider
        // after a successful authentication flow (e.g Google or Facebook).
        await _signInManager.SignOutAsync();

        // Returning a SignOutResult will ask OpenIddict to redirect the user agent
        // to the post_logout_redirect_uri specified by the client application or to
        // the RedirectUri specified in the authentication properties if none was set.
        return SignOut(
            authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
            properties: new AuthenticationProperties
            {
                RedirectUri = "/"
            });
    }
    #endregion

    #region Password, authorization code, device and refresh token flows
    // Note: to support non-interactive flows like password,
    // you must provide your own token endpoint action:

    [HttpPost("~/connect/token"), Produces("application/json")]
    public async Task<IActionResult> Exchange()
    {
        var request = HttpContext.GetOpenIddictServerRequest() ??
            throw new InvalidOperationException("The OpenID Connect request cannot be retrieved.");

        if (request.IsPasswordGrantType())
        {
            var user = await _userManager.FindByNameAsync(request.Username);
            if (user is null)
            {
                return Forbid(
                    authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
                    properties: new AuthenticationProperties(new Dictionary<string, string>
                    {
                        [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.InvalidGrant,
                        [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] = "The username/password couple is invalid."
                    }));
            }

            // Validate the username/password parameters and ensure the account is not locked out.
            var result = await _signInManager.CheckPasswordSignInAsync(user, request.Password, lockoutOnFailure: true);
            if (!result.Succeeded)
            {
                return Forbid(
                    authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
                    properties: new AuthenticationProperties(new Dictionary<string, string>
                    {
                        [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.InvalidGrant,
                        [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] = "The username/password couple is invalid."
                    }));
            }

            // Create the claims-based identity that will be used by OpenIddict to generate tokens.
            var identity = new ClaimsIdentity(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme)
                .AddClaim(Claims.Subject, await _userManager.GetUserIdAsync(user))
                .AddClaim(Claims.Email, await _userManager.GetEmailAsync(user))
                .AddClaim(Claims.Name, await _userManager.GetUserNameAsync(user))
                .AddClaims(Claims.Role, (await _userManager.GetRolesAsync(user)).ToImmutableArray());

            // Note: in this sample, the granted scopes match the requested scope
            // but you may want to allow the user to uncheck specific scopes.
            // For that, simply restrict the list of scopes before calling SetScopes.
            identity.SetScopes(request.GetScopes());
            identity.SetResources(await _scopeManager.ListResourcesAsync(identity.GetScopes()).ToListAsync());
            identity.SetDestinations(GetDestinations);

            // Returning a SignInResult will ask OpenIddict to issue the appropriate access/identity tokens.
            return SignIn(new ClaimsPrincipal(identity), OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
        }

        else if (request.IsAuthorizationCodeGrantType() || request.IsDeviceCodeGrantType() || request.IsRefreshTokenGrantType())
        {
            // Retrieve the claims principal stored in the authorization code/device code/refresh token.
            var principal = (await HttpContext.AuthenticateAsync(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme)).Principal;

            // Retrieve the user profile corresponding to the authorization code/refresh token.
            var user = await _userManager.FindByIdAsync(principal.GetClaim(Claims.Subject));
            if (user is null)
            {
                return Forbid(
                    authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
                    properties: new AuthenticationProperties(new Dictionary<string, string>
                    {
                        [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.InvalidGrant,
                        [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] = "The token is no longer valid."
                    }));
            }

            // Ensure the user is still allowed to sign in.
            if (!await _signInManager.CanSignInAsync(user))
            {
                return Forbid(
                    authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
                    properties: new AuthenticationProperties(new Dictionary<string, string>
                    {
                        [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.InvalidGrant,
                        [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] = "The user is no longer allowed to sign in."
                    }));
            }

            principal.SetDestinations(GetDestinations);

            // Returning a SignInResult will ask OpenIddict to issue the appropriate access/identity tokens.
            return SignIn(principal, OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
        }

        throw new InvalidOperationException("The specified grant type is not supported.");
    }
    #endregion

    private IEnumerable<string> GetDestinations(Claim claim)
    {
        // Note: by default, claims are NOT automatically included in the access and identity tokens.
        // To allow OpenIddict to serialize them, you must attach them a destination, that specifies
        // whether they should be included in access tokens, in identity tokens or in both.

        switch (claim.Type)
        {
            case Claims.Name:
                yield return Destinations.AccessToken;

                if (claim.Subject.HasScope(Scopes.Profile))
                    yield return Destinations.IdentityToken;

                yield break;

            case Claims.Email:
                yield return Destinations.AccessToken;

                if (claim.Subject.HasScope(Scopes.Email))
                    yield return Destinations.IdentityToken;

                yield break;

            case Claims.Role:
                yield return Destinations.AccessToken;

                if (claim.Subject.HasScope(Scopes.Roles))
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
