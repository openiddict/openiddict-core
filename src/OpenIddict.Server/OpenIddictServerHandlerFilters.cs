/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using System.ComponentModel;
using System.Threading.Tasks;
using JetBrains.Annotations;
using static OpenIddict.Server.OpenIddictServerEvents;

namespace OpenIddict.Server
{
    [EditorBrowsable(EditorBrowsableState.Advanced)]
    public static class OpenIddictServerHandlerFilters
    {
        /// <summary>
        /// Represents a filter that excludes the associated handlers if no access token is returned.
        /// </summary>
        public class RequireAccessTokenIncluded : IOpenIddictServerHandlerFilter<ProcessSigninResponseContext>
        {
            public Task<bool> IsActiveAsync([NotNull] ProcessSigninResponseContext context)
            {
                if (context == null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                return Task.FromResult(context.IncludeAccessToken);
            }
        }

        /// <summary>
        /// Represents a filter that excludes the associated handlers if no authorization code is returned.
        /// </summary>
        public class RequireAuthorizationCodeIncluded : IOpenIddictServerHandlerFilter<ProcessSigninResponseContext>
        {
            public Task<bool> IsActiveAsync([NotNull] ProcessSigninResponseContext context)
            {
                if (context == null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                return Task.FromResult(context.IncludeAuthorizationCode);
            }
        }

        /// <summary>
        /// Represents a filter that excludes the associated handlers when no client identifier is received.
        /// </summary>
        public class RequireClientIdParameter : IOpenIddictServerHandlerFilter<BaseContext>
        {
            public Task<bool> IsActiveAsync([NotNull] BaseContext context)
            {
                if (context == null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                return Task.FromResult(!string.IsNullOrEmpty(context.Request.ClientId));
            }
        }

        /// <summary>
        /// Represents a filter that excludes the associated handlers if the degraded mode was not enabled.
        /// </summary>
        public class RequireDegradedModeDisabled : IOpenIddictServerHandlerFilter<BaseContext>
        {
            public Task<bool> IsActiveAsync([NotNull] BaseContext context)
            {
                if (context == null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                return Task.FromResult(!context.Options.EnableDegradedMode);
            }
        }

        /// <summary>
        /// Represents a filter that excludes the associated handlers if the degraded mode was enabled.
        /// </summary>
        public class RequireDegradedModeEnabled : IOpenIddictServerHandlerFilter<BaseContext>
        {
            public Task<bool> IsActiveAsync([NotNull] BaseContext context)
            {
                if (context == null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                return Task.FromResult(context.Options.EnableDegradedMode);
            }
        }

        /// <summary>
        /// Represents a filter that excludes the associated handlers if endpoint permissions were disabled.
        /// </summary>
        public class RequireEndpointPermissionsEnabled : IOpenIddictServerHandlerFilter<BaseContext>
        {
            public Task<bool> IsActiveAsync([NotNull] BaseContext context)
            {
                if (context == null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                return Task.FromResult(!context.Options.IgnoreEndpointPermissions);
            }
        }

        /// <summary>
        /// Represents a filter that excludes the associated handlers if grant type permissions were disabled.
        /// </summary>
        public class RequireGrantTypePermissionsEnabled : IOpenIddictServerHandlerFilter<BaseContext>
        {
            public Task<bool> IsActiveAsync([NotNull] BaseContext context)
            {
                if (context == null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                return Task.FromResult(!context.Options.IgnoreGrantTypePermissions);
            }
        }

        /// <summary>
        /// Represents a filter that excludes the associated handlers if no identity token is returned.
        /// </summary>
        public class RequireIdentityTokenIncluded : IOpenIddictServerHandlerFilter<ProcessSigninResponseContext>
        {
            public Task<bool> IsActiveAsync([NotNull] ProcessSigninResponseContext context)
            {
                if (context == null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                return Task.FromResult(context.IncludeIdentityToken);
            }
        }

        /// <summary>
        /// Represents a filter that excludes the associated handlers when no post_logout_redirect_uri is received.
        /// </summary>
        public class RequirePostLogoutRedirectUriParameter : IOpenIddictServerHandlerFilter<BaseContext>
        {
            public Task<bool> IsActiveAsync([NotNull] BaseContext context)
            {
                if (context == null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                return Task.FromResult(!string.IsNullOrEmpty(context.Request.PostLogoutRedirectUri));
            }
        }

        /// <summary>
        /// Represents a filter that excludes the associated handlers if no refresh token is returned.
        /// </summary>
        public class RequireRefreshTokenIncluded : IOpenIddictServerHandlerFilter<ProcessSigninResponseContext>
        {
            public Task<bool> IsActiveAsync([NotNull] ProcessSigninResponseContext context)
            {
                if (context == null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                return Task.FromResult(context.IncludeRefreshToken);
            }
        }

        /// <summary>
        /// Represents a filter that excludes the associated handlers if scope permissions were disabled.
        /// </summary>
        public class RequireScopePermissionsEnabled : IOpenIddictServerHandlerFilter<BaseContext>
        {
            public Task<bool> IsActiveAsync([NotNull] BaseContext context)
            {
                if (context == null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                return Task.FromResult(!context.Options.IgnoreScopePermissions);
            }
        }

        /// <summary>
        /// Represents a filter that excludes the associated handlers if scope validation was not enabled.
        /// </summary>
        public class RequireScopeValidationEnabled : IOpenIddictServerHandlerFilter<BaseContext>
        {
            public Task<bool> IsActiveAsync([NotNull] BaseContext context)
            {
                if (context == null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                return Task.FromResult(!context.Options.DisableScopeValidation);
            }
        }
    }
}
