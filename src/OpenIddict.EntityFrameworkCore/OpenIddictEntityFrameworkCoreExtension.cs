/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using System.ComponentModel;
using JetBrains.Annotations;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.Extensions.DependencyInjection;
using OpenIddict.EntityFrameworkCore.Models;

namespace OpenIddict.EntityFrameworkCore
{
    [EditorBrowsable(EditorBrowsableState.Never)]
    public class OpenIddictEntityFrameworkCoreExtension<TApplication, TAuthorization, TScope, TToken, TKey> : IDbContextOptionsExtension
        where TApplication : OpenIddictApplication<TKey, TAuthorization, TToken>
        where TAuthorization : OpenIddictAuthorization<TKey, TApplication, TToken>
        where TScope : OpenIddictScope<TKey>
        where TToken : OpenIddictToken<TKey, TApplication, TAuthorization>
        where TKey : IEquatable<TKey>
    {
        public void ApplyServices([NotNull] IServiceCollection services)
        {
            if (services == null)
            {
                throw new ArgumentNullException(nameof(services));
            }

            services.AddSingleton<IModelCustomizer, OpenIddictEntityFrameworkCoreCustomizer<
                TApplication, TAuthorization, TScope, TToken, TKey>>();
        }
    }
}
