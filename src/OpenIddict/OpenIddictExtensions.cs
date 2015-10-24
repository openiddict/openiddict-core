/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using Microsoft.AspNet.Identity;
using Microsoft.Extensions.Internal;
using OpenIddict;
using OpenIddict.Models;

namespace Microsoft.AspNet.Builder {
    public static class OpenIddictExtensions {
        public static OpenIddictServices AddOpenIddict([NotNull] this IdentityBuilder builder) {
            return builder.AddOpenIddictCore<Application>()
                          .AddEntityFrameworkStore();
        }

        public static OpenIddictServices AddOpenIddict<TApplication>([NotNull] this IdentityBuilder builder)
            where TApplication : Application {
            return builder.AddOpenIddictCore<TApplication>()
                          .AddEntityFrameworkStore();
        }
    }
}