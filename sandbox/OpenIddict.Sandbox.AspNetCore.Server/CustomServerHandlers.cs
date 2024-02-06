using System.Globalization;
using System.Security.Claims;
using System.Security.Principal;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.Abstractions;
using OpenIddict.Server;
using static OpenIddict.Abstractions.OpenIddictConstants;
using static OpenIddict.Server.OpenIddictServerEvents;
using static OpenIddict.Server.OpenIddictServerHandlerFilters;
using static OpenIddict.Server.OpenIddictServerHandlers;
using static OpenIddict.Server.OpenIddictServerHandlers.Protection;

namespace OpenIddict.Sandbox.AspNetCore.Server
{

    public class CustomServerHandlers
    {
        public class StarveRefreshTokenPrincipal : IOpenIddictServerHandler<ProcessSignInContext>
        {
            public StarveRefreshTokenPrincipal()
            {
            }

            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessSignInContext>()
                    .AddFilter<RequireRefreshTokenGenerated>()
                    .UseScopedHandler<StarveRefreshTokenPrincipal>(static provider =>
                    {
                        return new StarveRefreshTokenPrincipal();
                    })
                    .SetOrder(PrepareRefreshTokenPrincipal.Descriptor.Order + 1)
                    .SetType(OpenIddictServerHandlerType.Custom)
                    .Build();


            public ValueTask HandleAsync(OpenIddictServerEvents.ProcessSignInContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                if (context.RefreshTokenPrincipal is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                var principal = context.RefreshTokenPrincipal.Clone(claim =>
                {
                    if (
                        string.Equals(claim.Type, Claims.Private.CreationDate, StringComparison.OrdinalIgnoreCase) ||
                        string.Equals(claim.Type, Claims.Private.AuthorizationId, StringComparison.OrdinalIgnoreCase) ||
                        string.Equals(claim.Type, Claims.Private.ExpirationDate, StringComparison.OrdinalIgnoreCase)
                        )
                    {
                        return true;
                    }
                    return false;
                });

                foreach (Claim claim in principal.Claims)
                {
                    claim.SetDestinations(null);//clean out the destionations,  these are contributing to the bloated token size.
                }

                context.RefreshTokenPrincipal = principal;

                return default;
            }

        }

        public sealed class RemoveRefreshTokenEncryption : IOpenIddictServerHandler<GenerateTokenContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<GenerateTokenContext>()
                    .AddFilter<RequireJsonWebTokenFormat>()
                    .UseSingletonHandler<RemoveRefreshTokenEncryption>()
                    .SetOrder(CreateTokenEntry.Descriptor.Order + 999) //THIS must run right before GenerateIdentityModelToken
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(GenerateTokenContext context) { 
                if(context.TokenType == TokenTypeHints.RefreshToken)
                {
                    context.EncryptionCredentials = null;
                }
                return default;
            }
        } 


        public sealed class RehydrateRefreshToken : IOpenIddictServerHandler<ValidateTokenContext>
        {
            IOpenIddictAuthorizationManager _authorizationManager { get; }
            public RehydrateRefreshToken(IOpenIddictAuthorizationManager authorizationManager)
            {
                _authorizationManager = authorizationManager;
            }

            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ValidateTokenContext>()
                    .UseScopedHandler<RehydrateRefreshToken>(static provider =>
                    {
                        var options = provider.GetRequiredService<IOptionsMonitor<OpenIddictServerOptions>>().CurrentValue;
                        return new RehydrateRefreshToken(provider.GetService<IOpenIddictAuthorizationManager>());
                    })
                    .SetOrder(ValidateReferenceTokenIdentifier.Descriptor.Order + 999)//this should put it just ahead of:  ValidateIdentityModelToken
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();
            
            public async ValueTask HandleAsync(ValidateTokenContext context)
            {
                if(context.Request.GrantType != "refresh_token")
                {
                    return;
                }

                //ease of the validation rules because we dont have issuer, and we dont have an audience.
                //we are however accepting it when the token is correctly signed, and the validatetokenasync isnt failing
                var validation = context.TokenValidationParameters.Clone();
                validation.ValidateIssuer = false;
                validation.ValidateAudience = false;

                var token = await context.SecurityTokenHandler.ValidateTokenAsync(context.Token, validation);
                if (token==null)
                {
                    return;
                }

                if(!token.IsValid)
                {
                    throw new InvalidOperationException("Invalid token");
                }
                
                //build the claims back up with metadata.
                token.ClaimsIdentity.AddClaim(Claims.Private.Issuer, (context.Options.Issuer ?? context.BaseUri)?.AbsoluteUri);

                if(context.Request?.ClientId != null)
                {
                    token.ClaimsIdentity.SetClaim(Claims.Private.Presenter, context.Request.ClientId);
                }

                //creation date will be passed in as exp, but OIDT requries oi_exp and a different format.
                if (!token.ClaimsIdentity.HasClaim(Claims.Private.CreationDate))
                {
                    var date = token.ClaimsIdentity.GetClaim(Claims.IssuedAt);
                    if (!string.IsNullOrEmpty(date) &&
                        long.TryParse(date, NumberStyles.Integer, CultureInfo.InvariantCulture, out var value))
                    {
                        token.ClaimsIdentity.SetCreationDate(DateTimeOffset.FromUnixTimeSeconds(value));
                    }
                }
         
                //expiration date will be passed in as exp, but OIDT requries oi_exp and a different format.
                if (!token.ClaimsIdentity.HasClaim(Claims.Private.ExpirationDate))
                {
                    var date = token.ClaimsIdentity.GetClaim(Claims.ExpiresAt);
                    if (!string.IsNullOrEmpty(date) &&
                        long.TryParse(date, NumberStyles.Integer, CultureInfo.InvariantCulture, out var value))
                    {
                        token.ClaimsIdentity.SetExpirationDate(DateTimeOffset.FromUnixTimeSeconds(value));
                    }
                }

                //hit the authorization table to get the subject and scopes.
                var authorization = await _authorizationManager.FindByIdAsync(token.ClaimsIdentity.GetClaim(Claims.Private.AuthorizationId));
                var subject = await _authorizationManager.GetSubjectAsync(authorization);
                var scopes = await _authorizationManager.GetScopesAsync(authorization);

                token.ClaimsIdentity.SetClaim(Claims.Subject, subject);
                foreach (var scope in scopes)
                {
                    token.ClaimsIdentity.AddClaim(Claims.Private.Scope, scope);
                }
                
                //we have two options, either regenerate a full token, and hand it down. or generate the principal
                context.Principal = new ClaimsPrincipal(token.ClaimsIdentity).SetTokenType(TokenTypeHints.RefreshToken);

                //var descriptor = new SecurityTokenDescriptor
                //{
                //    //Claims = claims,
                //    EncryptingCredentials = context.Options.EncryptionCredentials.First(),
                //    Expires = token.ClaimsIdentity.GetExpirationDate()?.UtcDateTime,
                //    IssuedAt = token.ClaimsIdentity.GetCreationDate()?.UtcDateTime,
                //    Issuer = token.ClaimsIdentity.GetClaim(Claims.Private.Issuer),
                //    SigningCredentials = context.Options.SigningCredentials.First(),
                //    Subject = token.ClaimsIdentity,
                //    TokenType = "oi_reft+jwt"// TokenTypeHints.RefreshToken
                //};
                //context.Token = context.SecurityTokenHandler.CreateToken(descriptor);

            }
        }
    }
}
