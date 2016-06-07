/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using JetBrains.Annotations;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace OpenIddict.Infrastructure {
    /// <summary>
    /// Exposes the common services used by OpenIddict.
    /// </summary>
    public class OpenIddictServices<TUser, TApplication, TAuthorization, TScope, TToken>
        where TUser : class where TApplication : class where TAuthorization : class
        where TScope : class where TToken : class {
        public OpenIddictServices([NotNull] IServiceProvider services) {
            Services = services;
        }

        /// <summary>
        /// Gets the <see cref="OpenIddictApplicationManager{TApplication}"/>.
        /// </summary>
        public virtual OpenIddictApplicationManager<TApplication> Applications =>
            Services.GetRequiredService<OpenIddictApplicationManager<TApplication>>();

        /// <summary>
        /// Gets the optional <see cref="HttpContext"/>.
        /// </summary>
        public virtual HttpContext Context => Services.GetService<IHttpContextAccessor>()?.HttpContext;

        /// <summary>
        /// Gets the <see cref="ILogger"/>.
        /// </summary>
        public virtual ILogger Logger =>
            Services.GetRequiredService<ILogger<OpenIddictProvider<TUser, TApplication, TAuthorization, TScope, TToken>>>();

        /// <summary>
        /// Gets the <see cref="OpenIddictOptions"/>.
        /// </summary>
        public virtual OpenIddictOptions Options => Services.GetRequiredService<IOptions<OpenIddictOptions>>().Value;

        /// <summary>
        /// Gets the <see cref="IServiceProvider"/> used to resolve services.
        /// </summary>
        public virtual IServiceProvider Services { get; }

        /// <summary>
        /// Gets the <see cref="SignInManager{TUser}"/>.
        /// </summary>
        public virtual SignInManager<TUser> SignIn => Services.GetRequiredService<SignInManager<TUser>>();

        /// <summary>
        /// Gets the <see cref="OpenIddictTokenManager{TToken}"/>.
        /// </summary>
        public virtual OpenIddictTokenManager<TToken> Tokens => Services.GetRequiredService<OpenIddictTokenManager<TToken>>();

        /// <summary>
        /// Gets the <see cref="OpenIddictUserManager{TUser}"/>.
        /// </summary>
        public virtual OpenIddictUserManager<TUser> Users => Services.GetRequiredService<OpenIddictUserManager<TUser>>();
    }
}