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

namespace OpenIddict {
    /// <summary>
    /// Exposes the common services used by OpenIddict.
    /// </summary>
    public class OpenIddictServices<TUser, TApplication> where TUser : class where TApplication : class {
        public OpenIddictServices([NotNull] IServiceProvider services) {
            Services = services;
        }

        /// <summary>
        /// Gets the <see cref="OpenIddictManager{TUser, TApplication}"/>.
        /// </summary>
        public virtual OpenIddictManager<TUser, TApplication> Applications {
            get { return Services.GetRequiredService<OpenIddictManager<TUser, TApplication>>(); }
        }

        /// <summary>
        /// Gets the optional <see cref="HttpContext"/>.
        /// </summary>
        public virtual HttpContext Context {
            get { return Services.GetService<IHttpContextAccessor>()?.HttpContext; }
        }

        /// <summary>
        /// Gets the <see cref="ILogger"/>.
        /// </summary>
        public virtual ILogger Logger {
            get { return Services.GetRequiredService<ILogger<OpenIddictManager<TUser, TApplication>>>(); }
        }

        /// <summary>
        /// Gets the <see cref="IServiceProvider"/> used to resolve services.
        /// </summary>
        public virtual IServiceProvider Services { get; }

        /// <summary>
        /// Gets the <see cref="SignInManager{TUser}"/>.
        /// </summary>
        public virtual SignInManager<TUser> SignIn {
            get { return Services.GetRequiredService<SignInManager<TUser>>(); }
        }

        /// <summary>
        /// Gets the <see cref="IOpenIddictStore{TUser, TApplication}"/>.
        /// </summary>
        public virtual IOpenIddictStore<TUser, TApplication> Store {
            get { return Services.GetRequiredService<IOpenIddictStore<TUser, TApplication>>(); }
        }

        /// <summary>
        /// Gets the <see cref="UserManager{TUser}"/>.
        /// </summary>
        public virtual UserManager<TUser> Users {
            get { return Services.GetRequiredService<UserManager<TUser>>(); }
        }
    }
}