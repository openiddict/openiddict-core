/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using System.ComponentModel;
using System.Threading.Tasks;
using static OpenIddict.Server.OpenIddictServerEvents;

namespace OpenIddict.Server
{
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

                return new ValueTask<bool>(context.GenerateAccessToken);
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

                return new ValueTask<bool>(context.GenerateAuthorizationCode);
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

                return new ValueTask<bool>(context.EndpointType == OpenIddictServerEndpointType.Authorization);
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

                return new ValueTask<bool>(!context.Options.DisableAuthorizationStorage);
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

                return new ValueTask<bool>(!string.IsNullOrEmpty(context.Transaction.Request?.ClientId));
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

                return new ValueTask<bool>(context.EndpointType == OpenIddictServerEndpointType.Configuration);
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

                return new ValueTask<bool>(context.EndpointType == OpenIddictServerEndpointType.Cryptography);
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

                return new ValueTask<bool>(!context.Options.EnableDegradedMode);
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

                return new ValueTask<bool>(context.GenerateDeviceCode);
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

                return new ValueTask<bool>(context.EndpointType == OpenIddictServerEndpointType.Device);
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

                return new ValueTask<bool>(!context.Options.IgnoreEndpointPermissions);
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

                return new ValueTask<bool>(!context.Options.IgnoreGrantTypePermissions);
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

                return new ValueTask<bool>(context.GenerateIdentityToken);
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

                return new ValueTask<bool>(context.EndpointType == OpenIddictServerEndpointType.Introspection);
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

                return new ValueTask<bool>(context.EndpointType == OpenIddictServerEndpointType.Logout);
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

                return new ValueTask<bool>(!string.IsNullOrEmpty(context.Transaction.Request?.PostLogoutRedirectUri));
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

                return new ValueTask<bool>(context.Options.UseReferenceAccessTokens);
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

                return new ValueTask<bool>(context.Options.UseReferenceRefreshTokens);
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

                return new ValueTask<bool>(context.GenerateRefreshToken);
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

                return new ValueTask<bool>(!context.Options.IgnoreResponseTypePermissions);
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

                return new ValueTask<bool>(context.EndpointType == OpenIddictServerEndpointType.Revocation);
            }
        }

        /// <summary>
        /// Represents a filter that excludes the associated handlers if rolling tokens were enabled.
        /// </summary>
        public class RequireRollingTokensDisabled : IOpenIddictServerHandlerFilter<BaseContext>
        {
            public ValueTask<bool> IsActiveAsync(BaseContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                return new ValueTask<bool>(!context.Options.UseRollingRefreshTokens);
            }
        }

        /// <summary>
        /// Represents a filter that excludes the associated handlers if rolling refresh tokens were not enabled.
        /// </summary>
        public class RequireRollingRefreshTokensEnabled : IOpenIddictServerHandlerFilter<BaseContext>
        {
            public ValueTask<bool> IsActiveAsync(BaseContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                return new ValueTask<bool>(context.Options.UseRollingRefreshTokens);
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

                return new ValueTask<bool>(!context.Options.IgnoreScopePermissions);
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

                return new ValueTask<bool>(!context.Options.DisableScopeValidation);
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

                return new ValueTask<bool>(!context.Options.DisableSlidingRefreshTokenExpiration);
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

                return new ValueTask<bool>(context.EndpointType == OpenIddictServerEndpointType.Token);
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

                return new ValueTask<bool>(!context.Options.DisableTokenStorage);
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

                return new ValueTask<bool>(context.GenerateUserCode);
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

                return new ValueTask<bool>(context.EndpointType == OpenIddictServerEndpointType.Userinfo);
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

                return new ValueTask<bool>(context.EndpointType == OpenIddictServerEndpointType.Verification);
            }
        }
    }
}
