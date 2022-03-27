/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.ComponentModel;

namespace OpenIddict.Client;

[EditorBrowsable(EditorBrowsableState.Advanced)]
public static class OpenIddictClientHandlerFilters
{
    /// <summary>
    /// Represents a filter that excludes the associated handlers if the challenge
    /// doesn't correspond to an authorization code or implicit grant operation.
    /// </summary>
    public class RequireAuthorizationCodeOrImplicitGrantType : IOpenIddictClientHandlerFilter<ProcessChallengeContext>
    {
        public ValueTask<bool> IsActiveAsync(ProcessChallengeContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            return new ValueTask<bool>(context.GrantType is GrantTypes.AuthorizationCode or GrantTypes.Implicit);
        }
    }

    /// <summary>
    /// Represents a filter that excludes the associated handlers if no authorization code is validated.
    /// </summary>
    public class RequireAuthorizationCodeValidated : IOpenIddictClientHandlerFilter<ProcessAuthenticationContext>
    {
        public ValueTask<bool> IsActiveAsync(ProcessAuthenticationContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            return new ValueTask<bool>(context.ValidateAuthorizationCode);
        }
    }

    /// <summary>
    /// Represents a filter that excludes the associated handlers if no backchannel access token is validated.
    /// </summary>
    public class RequireBackchannelAccessTokenValidated : IOpenIddictClientHandlerFilter<ProcessAuthenticationContext>
    {
        public ValueTask<bool> IsActiveAsync(ProcessAuthenticationContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            return new ValueTask<bool>(context.ValidateBackchannelAccessToken);
        }
    }

    /// <summary>
    /// Represents a filter that excludes the associated handlers if no backchannel identity token principal is available.
    /// </summary>
    public class RequireBackchannelIdentityTokenPrincipal : IOpenIddictClientHandlerFilter<ProcessAuthenticationContext>
    {
        public ValueTask<bool> IsActiveAsync(ProcessAuthenticationContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            return new ValueTask<bool>(context.BackchannelIdentityTokenPrincipal is not null);
        }
    }

    /// <summary>
    /// Represents a filter that excludes the associated handlers if no backchannel identity token is validated.
    /// </summary>
    public class RequireBackchannelIdentityTokenValidated : IOpenIddictClientHandlerFilter<ProcessAuthenticationContext>
    {
        public ValueTask<bool> IsActiveAsync(ProcessAuthenticationContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            return new ValueTask<bool>(context.ValidateBackchannelIdentityToken);
        }
    }

    /// <summary>
    /// Represents a filter that excludes the associated handlers if no frontchannel access token is validated.
    /// </summary>
    public class RequireFrontchannelAccessTokenValidated : IOpenIddictClientHandlerFilter<ProcessAuthenticationContext>
    {
        public ValueTask<bool> IsActiveAsync(ProcessAuthenticationContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            return new ValueTask<bool>(context.ValidateFrontchannelAccessToken);
        }
    }

    /// <summary>
    /// Represents a filter that excludes the associated handlers if no frontchannel identity token principal is available.
    /// </summary>
    public class RequireFrontchannelIdentityTokenPrincipal : IOpenIddictClientHandlerFilter<ProcessAuthenticationContext>
    {
        public ValueTask<bool> IsActiveAsync(ProcessAuthenticationContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            return new ValueTask<bool>(context.FrontchannelIdentityTokenPrincipal is not null);
        }
    }

    /// <summary>
    /// Represents a filter that excludes the associated handlers if no frontchannel identity token is validated.
    /// </summary>
    public class RequireFrontchannelIdentityTokenValidated : IOpenIddictClientHandlerFilter<ProcessAuthenticationContext>
    {
        public ValueTask<bool> IsActiveAsync(ProcessAuthenticationContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            return new ValueTask<bool>(context.ValidateFrontchannelIdentityToken);
        }
    }

    /// <summary>
    /// Represents a filter that excludes the associated handlers if the request is not a redirection request.
    /// </summary>
    public class RequireRedirectionRequest : IOpenIddictClientHandlerFilter<BaseContext>
    {
        public ValueTask<bool> IsActiveAsync(BaseContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            return new ValueTask<bool>(context.EndpointType == OpenIddictClientEndpointType.Redirection);
        }
    }

    /// <summary>
    /// Represents a filter that excludes the associated handlers if no refresh token is validated.
    /// </summary>
    public class RequireRefreshTokenValidated : IOpenIddictClientHandlerFilter<ProcessAuthenticationContext>
    {
        public ValueTask<bool> IsActiveAsync(ProcessAuthenticationContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            return new ValueTask<bool>(context.ValidateRefreshToken);
        }
    }

    /// <summary>
    /// Represents a filter that excludes the associated handlers if no state token is generated.
    /// </summary>
    public class RequireStateTokenGenerated : IOpenIddictClientHandlerFilter<ProcessChallengeContext>
    {
        public ValueTask<bool> IsActiveAsync(ProcessChallengeContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            return new ValueTask<bool>(context.GenerateStateToken);
        }
    }

    /// <summary>
    /// Represents a filter that excludes the associated handlers if no state token principal is available.
    /// </summary>
    public class RequireStateTokenPrincipal : IOpenIddictClientHandlerFilter<ProcessAuthenticationContext>
    {
        public ValueTask<bool> IsActiveAsync(ProcessAuthenticationContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            return new ValueTask<bool>(context.StateTokenPrincipal is not null);
        }
    }

    /// <summary>
    /// Represents a filter that excludes the associated handlers if no state token is validated.
    /// </summary>
    public class RequireStateTokenValidated : IOpenIddictClientHandlerFilter<ProcessAuthenticationContext>
    {
        public ValueTask<bool> IsActiveAsync(ProcessAuthenticationContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            return new ValueTask<bool>(context.ValidateStateToken);
        }
    }

    /// <summary>
    /// Represents a filter that excludes the associated handlers if no token request is expected to be sent.
    /// </summary>
    public class RequireTokenRequest : IOpenIddictClientHandlerFilter<ProcessAuthenticationContext>
    {
        public ValueTask<bool> IsActiveAsync(ProcessAuthenticationContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            return new ValueTask<bool>(context.TokenRequest is not null);
        }
    }

    /// <summary>
    /// Represents a filter that excludes the associated handlers if no token response was received.
    /// </summary>
    public class RequireTokenResponse : IOpenIddictClientHandlerFilter<ProcessAuthenticationContext>
    {
        public ValueTask<bool> IsActiveAsync(ProcessAuthenticationContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            return new ValueTask<bool>(context.TokenResponse is not null);
        }
    }

    /// <summary>
    /// Represents a filter that excludes the associated handlers if no userinfo request is expected to be sent.
    /// </summary>
    public class RequireUserinfoRequest : IOpenIddictClientHandlerFilter<ProcessAuthenticationContext>
    {
        public ValueTask<bool> IsActiveAsync(ProcessAuthenticationContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            return new ValueTask<bool>(context.UserinfoRequest is not null);
        }
    }

    /// <summary>
    /// Represents a filter that excludes the associated handlers if no userinfo response was received.
    /// </summary>
    public class RequireUserinfoResponse : IOpenIddictClientHandlerFilter<ProcessAuthenticationContext>
    {
        public ValueTask<bool> IsActiveAsync(ProcessAuthenticationContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            return new ValueTask<bool>(context.UserinfoResponse is not null);
        }
    }

    /// <summary>
    /// Represents a filter that excludes the associated handlers if no userinfo token is extracted.
    /// </summary>
    public class RequireUserinfoTokenExtracted : IOpenIddictClientHandlerFilter<ProcessAuthenticationContext>
    {
        public ValueTask<bool> IsActiveAsync(ProcessAuthenticationContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            return new ValueTask<bool>(context.ExtractUserinfoToken);
        }
    }

    /// <summary>
    /// Represents a filter that excludes the associated handlers if no userinfo token principal is available.
    /// </summary>
    public class RequireUserinfoTokenPrincipal : IOpenIddictClientHandlerFilter<ProcessAuthenticationContext>
    {
        public ValueTask<bool> IsActiveAsync(ProcessAuthenticationContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            return new ValueTask<bool>(context.UserinfoTokenPrincipal is not null);
        }
    }
}
