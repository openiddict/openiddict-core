/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.ComponentModel;
using AspNet.Security.OpenIdConnect.Server;
using JetBrains.Annotations;
using Microsoft.Extensions.Logging;
using OpenIddict.Core;

namespace OpenIddict
{
    /// <summary>
    /// Provides the logic necessary to extract, validate and handle OpenID Connect requests.
    /// </summary>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public partial class OpenIddictProvider<TApplication, TAuthorization, TScope, TToken> : OpenIdConnectServerProvider
        where TApplication : class where TAuthorization : class where TScope : class where TToken : class
    {
        /// <summary>
        /// Creates a new instance of the <see cref="OpenIddictProvider{TApplication, TAuthorization, TScope, TToken}"/> class.
        /// </summary>
        public OpenIddictProvider(
            [NotNull] ILogger<OpenIddictProvider<TApplication, TAuthorization, TScope, TToken>> logger,
            [NotNull] OpenIddictApplicationManager<TApplication> applications,
            [NotNull] OpenIddictAuthorizationManager<TAuthorization> authorizations,
            [NotNull] OpenIddictScopeManager<TScope> scopes,
            [NotNull] OpenIddictTokenManager<TToken> tokens)
        {
            Applications = applications;
            Authorizations = authorizations;
            Logger = logger;
            Scopes = scopes;
            Tokens = tokens;
        }

        /// <summary>
        /// Gets the applications manager.
        /// </summary>
        public OpenIddictApplicationManager<TApplication> Applications { get; }

        /// <summary>
        /// Gets the authorizations manager.
        /// </summary>
        public OpenIddictAuthorizationManager<TAuthorization> Authorizations { get; }

        /// <summary>
        /// Gets the logger associated with the current class.
        /// </summary>
        public ILogger Logger { get; }

        /// <summary>
        /// Gets the scopes manager.
        /// </summary>
        public OpenIddictScopeManager<TScope> Scopes { get; }

        /// <summary>
        /// Gets the tokens manager.
        /// </summary>
        public OpenIddictTokenManager<TToken> Tokens { get; }
    }
}