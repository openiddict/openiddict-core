using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using OpenIddict.Client.AspNetCore;

namespace OpenIddict.Sandbox.AspNetCore.Server.Controllers;

public class AuthenticationController : Controller
{
    // Note: this controller uses the same callback action for all providers
    // but for users who prefer using a different action per provider,
    // the following action can be split into separate actions.
    [HttpGet("~/signin-{provider}"), HttpPost("~/signin-{provider}")]
    public async Task<ActionResult> Callback()
    {
        // Retrieve the authorization data validated by OpenIddict as part of the callback handling.
        var result = await HttpContext.AuthenticateAsync(OpenIddictClientAspNetCoreDefaults.AuthenticationScheme);

        // Multiple strategies exist to handle OAuth 2.0/OpenID Connect callbacks, each with their pros and cons:
        //
        //   * Directly using the tokens to perform the necessary action(s) on behalf of the user, which is suitable
        //     for applications that don't need a long-term access to the user's resources or don't want to store
        //     access/refresh tokens in a database or in an authentication cookie (which has security implications).
        //     It is also suitable for applications that don't need to authenticate users but only need to perform
        //     action(s) on their behalf by making API calls using the access token returned by the remote server.
        //
        //   * Storing the external claims/tokens in a database (and optionally keeping the essential claims in an
        //     authentication cookie so that cookie size limits are not hit). For the applications that use ASP.NET
        //     Core Identity, the UserManager.SetAuthenticationTokenAsync() API can be used to store external tokens.
        //
        //     Note: in this case, it's recommended to use column encryption to protect the tokens in the database.
        //
        //   * Storing the external claims/tokens in an authentication cookie, which doesn't require having
        //     a user database but may be affected by the cookie size limits enforced by most browser vendors
        //     (e.g Safari for macOS and Safari for iOS/iPadOS enforce a per-domain 4KB limit for all cookies).
        //
        //     Note: this is the approach used here, but the external claims are first filtered to only persist
        //     a few claims like the user identifier. The same approach is used to store the access/refresh tokens.

        // Important: if the remote server doesn't support OpenID Connect and doesn't expose a userinfo endpoint,
        // result.Principal.Identity will represent an unauthenticated identity and won't contain any claim.
        //
        // Such identities cannot be used as-is to build an authentication cookie in ASP.NET Core (as the
        // antiforgery stack requires at least a name claim to bind CSRF cookies to the user's identity) but
        // the access/refresh tokens can be retrieved using result.Properties.GetTokens() to make API calls.
        if (result.Principal.Identity is not ClaimsIdentity { IsAuthenticated: true })
        {
            throw new InvalidOperationException("The external authorization data cannot be used for authentication.");
        }

        // Build an identity based on the external claims and that will be used to create the authentication cookie.
        //
        // By default, all claims extracted during the authorization dance are available. The claims collection stored
        // in the cookie can be filtered out or mapped to different names depending the claim name or its issuer.
        var claims = new List<Claim>(result.Principal.Claims
            .Select(claim => claim switch
            {
                // Note: when using external authentication providers with ASP.NET Core Identity,
                // the ClaimTypes.NameIdentifier claim - which is not configurable in Identity -
                // MUST be used to store the user identifier.
                { Type: "id", Issuer: "https://github.com/" }
                    => new Claim(ClaimTypes.NameIdentifier, claim.Value, claim.ValueType, claim.Issuer),

                _ => claim
            })
            .Where(claim => claim switch
            {
                // Preserve the ClaimTypes.NameIdentifier claim.
                { Type: ClaimTypes.NameIdentifier } => true,

                // Applications that use multiple client registrations can filter claims based on the issuer.
                { Type: "bio", Issuer: "https://github.com/" } => true,

                // Don't preserve the other claims.
                _ => false
            }));

        // Note: when using external authentication providers with ASP.NET Core Identity,
        // the "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier" claim
        // - which is not configurable in Identity - MUST be used to store the user identifier.
        var identity = new ClaimsIdentity(claims,
            authenticationType: IdentityConstants.ExternalScheme,
            nameType: ClaimTypes.NameIdentifier,
            roleType: ClaimTypes.Role);

        // Build the authentication properties based on the properties that were added when the challenge was triggered.
        var properties = new AuthenticationProperties(result.Properties.Items);

        // If needed, the tokens returned by the authorization server can be stored in the authentication cookie.
        // To make cookies less heavy, tokens that are not used are filtered out before creating the cookie.
        properties.StoreTokens(result.Properties.GetTokens().Where(token => token switch
        {
            // Preserve the access and refresh tokens returned in the token response, if available.
            {
                Name: OpenIddictClientAspNetCoreConstants.Tokens.BackchannelAccessToken or
                      OpenIddictClientAspNetCoreConstants.Tokens.RefreshToken
            } => true,

            // Ignore the other tokens.
            _ => false
        }));

        // Note: "return SignIn(...)" cannot be directly used in this case, as the cookies handler doesn't allow
        // redirecting from an endpoint that doesn't match the path set in CookieAuthenticationOptions.LoginPath.
        // For more information about this restriction, visit https://github.com/dotnet/aspnetcore/issues/36934.
        await HttpContext.SignInAsync(IdentityConstants.ExternalScheme, new ClaimsPrincipal(identity), properties);

        return Redirect(properties.RedirectUri);
    }
}
