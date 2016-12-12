/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.Extensions.DependencyInjection;
using OpenIddict.Models;

namespace OpenIddict.EntityFrameworkCore {
    public class OpenIddictExtension<TApplication, TAuthorization, TScope, TToken, TKey> : IDbContextOptionsExtension
        where TApplication : OpenIddictApplication<TKey, TToken>
        where TAuthorization : OpenIddictAuthorization<TKey, TToken>
        where TScope : OpenIddictScope<TKey>
        where TToken : OpenIddictToken<TKey>
        where TKey : IEquatable<TKey> {
        public void ApplyServices(IServiceCollection services) {
            if (services == null) {
                throw new ArgumentNullException(nameof(services));
            }

            services.AddSingleton<IModelCustomizer, OpenIddictCustomizer<TApplication, TAuthorization, TScope, TToken, TKey>>();
        }
    }
}
