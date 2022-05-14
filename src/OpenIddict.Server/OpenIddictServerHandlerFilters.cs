/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.ComponentModel;

namespace OpenIddict.Server;

[EditorBrowsable(EditorBrowsableState.Advanced)]
public static class OpenIddictServerHandlerFilters
{
    /// <summary>
    /// Represents a filter that excludes the associated handlers if no access token is generated.
    /// </summary>
    public class RequireAccessTokenGenerated : IOpenIddictServerHandlerFilter<ProcessSignInContext>
    {
        public ValueTask<bool> IsActiveAsync(ProcessSignInContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            return new(context.GenerateAccessToken);
        }
    }

    /// <summary>
    /// Represents a filter that excludes the associated handlers if no access token is validated.
    /// </summary>
    public class RequireAccessTokenValidated : IOpenIddictServerHandlerFilter<ProcessAuthenticationContext>
    {
        public ValueTask<bool> IsActiveAsync(ProcessAuthenticationContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            return new(context.ValidateAccessToken);
        }
    }

    /// <summary>
    /// Represents a filter that excludes the associated handlers if no authorization code is generated.
    /// </summary>
    public class RequireAuthorizationCodeGenerated : IOpenIddictServerHandlerFilter<ProcessSignInContext>
    {
        public ValueTask<bool> IsActiveAsync(ProcessSignInContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            return new(context.GenerateAuthorizationCode);
        }
    }

    /// <summary>
    /// Represents a filter that excludes the associated handlers if no authorization code is validated.
    /// </summary>
    public class RequireAuthorizationCodeValidated : IOpenIddictServerHandlerFilter<ProcessAuthenticationContext>
    {
        public ValueTask<bool> IsActiveAsync(ProcessAuthenticationContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            return new(context.ValidateAuthorizationCode);
        }
    }

    /// <summary>
    /// Represents a filter that excludes the associated handlers if the request is not an authorization request.
    /// </summary>
    public class RequireAuthorizationRequest : IOpenIddictServerHandlerFilter<BaseContext>
    {
        public ValueTask<bool> IsActiveAsync(BaseContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            return new(context.EndpointType is OpenIddictServerEndpointType.Authorization);
        }
    }

    /// <summary>
    /// Represents a filter that excludes the associated handlers if authorization storage was not enabled.
    /// </summary>
    public class RequireAuthorizationStorageEnabled : IOpenIddictServerHandlerFilter<BaseContext>
    {
        public ValueTask<bool> IsActiveAsync(BaseContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            return new(!context.Options.DisableAuthorizationStorage);
        }
    }

    /// <summary>
    /// Represents a filter that excludes the associated handlers when no client identifier is received.
    /// </summary>
    public class RequireClientIdParameter : IOpenIddictServerHandlerFilter<BaseContext>
    {
        public ValueTask<bool> IsActiveAsync(BaseContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            return new(!string.IsNullOrEmpty(context.Transaction.Request?.ClientId));
        }
    }

    /// <summary>
    /// Represents a filter that excludes the associated handlers if the request is not a configuration request.
    /// </summary>
    public class RequireConfigurationRequest : IOpenIddictServerHandlerFilter<BaseContext>
    {
        public ValueTask<bool> IsActiveAsync(BaseContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            return new(context.EndpointType is OpenIddictServerEndpointType.Configuration);
        }
    }

    /// <summary>
    /// Represents a filter that excludes the associated handlers if the request is not a cryptography request.
    /// </summary>
    public class RequireCryptographyRequest : IOpenIddictServerHandlerFilter<BaseContext>
    {
        public ValueTask<bool> IsActiveAsync(BaseContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            return new(context.EndpointType is OpenIddictServerEndpointType.Cryptography);
        }
    }

    /// <summary>
    /// Represents a filter that excludes the associated handlers if the degraded mode was not enabled.
    /// </summary>
    public class RequireDegradedModeDisabled : IOpenIddictServerHandlerFilter<BaseContext>
    {
        public ValueTask<bool> IsActiveAsync(BaseContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            return new(!context.Options.EnableDegradedMode);
        }
    }

    /// <summary>
    /// Represents a filter that excludes the associated handlers if no device code is generated.
    /// </summary>
    public class RequireDeviceCodeGenerated : IOpenIddictServerHandlerFilter<ProcessSignInContext>
    {
        public ValueTask<bool> IsActiveAsync(ProcessSignInContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            return new(context.GenerateDeviceCode);
        }
    }

    /// <summary>
    /// Represents a filter that excludes the associated handlers if no device code is validated.
    /// </summary>
    public class RequireDeviceCodeValidated : IOpenIddictServerHandlerFilter<ProcessAuthenticationContext>
    {
        public ValueTask<bool> IsActiveAsync(ProcessAuthenticationContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            return new(context.ValidateDeviceCode);
        }
    }

    /// <summary>
    /// Represents a filter that excludes the associated handlers if the request is not a device request.
    /// </summary>
    public class RequireDeviceRequest : IOpenIddictServerHandlerFilter<BaseContext>
    {
        public ValueTask<bool> IsActiveAsync(BaseContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            return new(context.EndpointType is OpenIddictServerEndpointType.Device);
        }
    }

    /// <summary>
    /// Represents a filter that excludes the associated handlers if endpoint permissions were disabled.
    /// </summary>
    public class RequireEndpointPermissionsEnabled : IOpenIddictServerHandlerFilter<BaseContext>
    {
        public ValueTask<bool> IsActiveAsync(BaseContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            return new(!context.Options.IgnoreEndpointPermissions);
        }
    }

    /// <summary>
    /// Represents a filter that excludes the associated handlers if no generic token is validated.
    /// </summary>
    public class RequireGenericTokenValidated : IOpenIddictServerHandlerFilter<ProcessAuthenticationContext>
    {
        public ValueTask<bool> IsActiveAsync(ProcessAuthenticationContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            return new(context.ValidateGenericToken);
        }
    }

    /// <summary>
    /// Represents a filter that excludes the associated handlers if grant type permissions were disabled.
    /// </summary>
    public class RequireGrantTypePermissionsEnabled : IOpenIddictServerHandlerFilter<BaseContext>
    {
        public ValueTask<bool> IsActiveAsync(BaseContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            return new(!context.Options.IgnoreGrantTypePermissions);
        }
    }

    /// <summary>
    /// Represents a filter that excludes the associated handlers if no identity token is generated.
    /// </summary>
    public class RequireIdentityTokenGenerated : IOpenIddictServerHandlerFilter<ProcessSignInContext>
    {
        public ValueTask<bool> IsActiveAsync(ProcessSignInContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            return new(context.GenerateIdentityToken);
        }
    }

    /// <summary>
    /// Represents a filter that excludes the associated handlers if no identity token is validated.
    /// </summary>
    public class RequireIdentityTokenValidated : IOpenIddictServerHandlerFilter<ProcessAuthenticationContext>
    {
        public ValueTask<bool> IsActiveAsync(ProcessAuthenticationContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            return new(context.ValidateIdentityToken);
        }
    }

    /// <summary>
    /// Represents a filter that excludes the associated handlers if the request is not an introspection request.
    /// </summary>
    public class RequireIntrospectionRequest : IOpenIddictServerHandlerFilter<BaseContext>
    {
        public ValueTask<bool> IsActiveAsync(BaseContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            return new(context.EndpointType is OpenIddictServerEndpointType.Introspection);
        }
    }

    /// <summary>
    /// Represents a filter that excludes the associated handlers if the selected token format is not JSON Web Token.
    /// </summary>
    public class RequireJsonWebTokenFormat : IOpenIddictServerHandlerFilter<GenerateTokenContext>
    {
        public ValueTask<bool> IsActiveAsync(GenerateTokenContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            return new(context.TokenFormat is TokenFormats.Jwt);
        }
    }

    /// <summary>
    /// Represents a filter that excludes the associated handlers if the request is not a logout request.
    /// </summary>
    public class RequireLogoutRequest : IOpenIddictServerHandlerFilter<BaseContext>
    {
        public ValueTask<bool> IsActiveAsync(BaseContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            return new(context.EndpointType is OpenIddictServerEndpointType.Logout);
        }
    }

    /// <summary>
    /// Represents a filter that excludes the associated handlers when no post_logout_redirect_uri is received.
    /// </summary>
    public class RequirePostLogoutRedirectUriParameter : IOpenIddictServerHandlerFilter<BaseContext>
    {
        public ValueTask<bool> IsActiveAsync(BaseContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            return new(!string.IsNullOrEmpty(context.Transaction.Request?.PostLogoutRedirectUri));
        }
    }

    /// <summary>
    /// Represents a filter that excludes the associated handlers if reference access tokens are disabled.
    /// </summary>
    public class RequireReferenceAccessTokensEnabled : IOpenIddictServerHandlerFilter<BaseContext>
    {
        public ValueTask<bool> IsActiveAsync(BaseContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            return new(context.Options.UseReferenceAccessTokens);
        }
    }

    /// <summary>
    /// Represents a filter that excludes the associated handlers if reference refresh tokens are disabled.
    /// </summary>
    public class RequireReferenceRefreshTokensEnabled : IOpenIddictServerHandlerFilter<BaseContext>
    {
        public ValueTask<bool> IsActiveAsync(BaseContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            return new(context.Options.UseReferenceRefreshTokens);
        }
    }

    /// <summary>
    /// Represents a filter that excludes the associated handlers if no refresh token is generated.
    /// </summary>
    public class RequireRefreshTokenGenerated : IOpenIddictServerHandlerFilter<ProcessSignInContext>
    {
        public ValueTask<bool> IsActiveAsync(ProcessSignInContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            return new(context.GenerateRefreshToken);
        }
    }

    /// <summary>
    /// Represents a filter that excludes the associated handlers if no refresh token is validated.
    /// </summary>
    public class RequireRefreshTokenValidated : IOpenIddictServerHandlerFilter<ProcessAuthenticationContext>
    {
        public ValueTask<bool> IsActiveAsync(ProcessAuthenticationContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            return new(context.ValidateRefreshToken);
        }
    }

    /// <summary>
    /// Represents a filter that excludes the associated handlers if response type permissions were disabled.
    /// </summary>
    public class RequireResponseTypePermissionsEnabled : IOpenIddictServerHandlerFilter<BaseContext>
    {
        public ValueTask<bool> IsActiveAsync(BaseContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            return new(!context.Options.IgnoreResponseTypePermissions);
        }
    }

    /// <summary>
    /// Represents a filter that excludes the associated handlers if the request is not a revocation request.
    /// </summary>
    public class RequireRevocationRequest : IOpenIddictServerHandlerFilter<BaseContext>
    {
        public ValueTask<bool> IsActiveAsync(BaseContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            return new(context.EndpointType is OpenIddictServerEndpointType.Revocation);
        }
    }

    /// <summary>
    /// Represents a filter that excludes the associated handlers if scope permissions were disabled.
    /// </summary>
    public class RequireScopePermissionsEnabled : IOpenIddictServerHandlerFilter<BaseContext>
    {
        public ValueTask<bool> IsActiveAsync(BaseContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            return new(!context.Options.IgnoreScopePermissions);
        }
    }

    /// <summary>
    /// Represents a filter that excludes the associated handlers if scope validation was not enabled.
    /// </summary>
    public class RequireScopeValidationEnabled : IOpenIddictServerHandlerFilter<BaseContext>
    {
        public ValueTask<bool> IsActiveAsync(BaseContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            return new(!context.Options.DisableScopeValidation);
        }
    }

    /// <summary>
    /// Represents a filter that excludes the associated handlers if sliding refresh token expiration was disabled.
    /// </summary>
    public class RequireSlidingRefreshTokenExpirationEnabled : IOpenIddictServerHandlerFilter<BaseContext>
    {
        public ValueTask<bool> IsActiveAsync(BaseContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            return new(!context.Options.DisableSlidingRefreshTokenExpiration);
        }
    }

    /// <summary>
    /// Represents a filter that excludes the associated handlers if no token entry is created in the database.
    /// </summary>
    public class RequireTokenEntryCreated : IOpenIddictServerHandlerFilter<GenerateTokenContext>
    {
        public ValueTask<bool> IsActiveAsync(GenerateTokenContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            return new(context.CreateTokenEntry);
        }
    }

    /// <summary>
    /// Represents a filter that excludes the associated handlers if token lifetime validation was disabled.
    /// </summary>
    public class RequireTokenLifetimeValidationEnabled : IOpenIddictServerHandlerFilter<ValidateTokenContext>
    {
        public ValueTask<bool> IsActiveAsync(ValidateTokenContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            return new(!context.DisableLifetimeValidation);
        }
    }

    /// <summary>
    /// Represents a filter that excludes the associated handlers if the token payload is not persisted in the database.
    /// </summary>
    public class RequireTokenPayloadPersisted : IOpenIddictServerHandlerFilter<GenerateTokenContext>
    {
        public ValueTask<bool> IsActiveAsync(GenerateTokenContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            return new(context.PersistTokenPayload);
        }
    }

    /// <summary>
    /// Represents a filter that excludes the associated handlers if the request is not a token request.
    /// </summary>
    public class RequireTokenRequest : IOpenIddictServerHandlerFilter<BaseContext>
    {
        public ValueTask<bool> IsActiveAsync(BaseContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            return new(context.EndpointType is OpenIddictServerEndpointType.Token);
        }
    }

    /// <summary>
    /// Represents a filter that excludes the associated handlers if token storage was not enabled.
    /// </summary>
    public class RequireTokenStorageEnabled : IOpenIddictServerHandlerFilter<BaseContext>
    {
        public ValueTask<bool> IsActiveAsync(BaseContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            return new(!context.Options.DisableTokenStorage);
        }
    }

    /// <summary>
    /// Represents a filter that excludes the associated handlers if no user code is generated.
    /// </summary>
    public class RequireUserCodeGenerated : IOpenIddictServerHandlerFilter<ProcessSignInContext>
    {
        public ValueTask<bool> IsActiveAsync(ProcessSignInContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            return new(context.GenerateUserCode);
        }
    }

    /// <summary>
    /// Represents a filter that excludes the associated handlers if no user code is validated.
    /// </summary>
    public class RequireUserCodeValidated : IOpenIddictServerHandlerFilter<ProcessAuthenticationContext>
    {
        public ValueTask<bool> IsActiveAsync(ProcessAuthenticationContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            return new(context.ValidateUserCode);
        }
    }

    /// <summary>
    /// Represents a filter that excludes the associated handlers if the request is not a userinfo request.
    /// </summary>
    public class RequireUserinfoRequest : IOpenIddictServerHandlerFilter<BaseContext>
    {
        public ValueTask<bool> IsActiveAsync(BaseContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            return new(context.EndpointType is OpenIddictServerEndpointType.Userinfo);
        }
    }

    /// <summary>
    /// Represents a filter that excludes the associated handlers if the request is not a verification request.
    /// </summary>
    public class RequireVerificationRequest : IOpenIddictServerHandlerFilter<BaseContext>
    {
        public ValueTask<bool> IsActiveAsync(BaseContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            return new(context.EndpointType is OpenIddictServerEndpointType.Verification);
        }
    }
}
