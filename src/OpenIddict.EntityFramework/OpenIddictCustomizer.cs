/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using JetBrains.Annotations;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.Extensions.DependencyInjection;
using OpenIddict.Models;

namespace OpenIddict.EntityFramework {
    /// <summary>
    /// Represents a model customizer able to register the entity sets
    /// required by the OpenIddict stack in an Entity Framework context.
    /// </summary>
    public class OpenIddictCustomizer<TApplication, TAuthorization, TScope, TToken, TKey> : ModelCustomizer
        where TApplication : OpenIddictApplication<TKey, TToken>
        where TAuthorization : OpenIddictAuthorization<TKey, TToken>
        where TScope : OpenIddictScope<TKey>
        where TToken : OpenIddictToken<TKey>
        where TKey : IEquatable<TKey> {
        public override void Customize([NotNull] ModelBuilder builder, [NotNull] DbContext context) {
            if (builder == null) {
                throw new ArgumentNullException(nameof(builder));
            }

            if (context == null) {
                throw new ArgumentNullException(nameof(context));
            }

            // Register the OpenIddict entity sets.
            builder.UseOpenIddict<TApplication, TAuthorization, TScope, TToken, TKey>();

            base.Customize(builder, context);
        }
    }
}