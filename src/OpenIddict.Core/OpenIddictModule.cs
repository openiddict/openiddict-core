/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using System.Diagnostics;
using JetBrains.Annotations;
using Microsoft.AspNetCore.Builder;

namespace OpenIddict {
    /// <summary>
    /// Represents an OpenIddict module.
    /// </summary>
    [DebuggerDisplay("{Name,nq}")]
    public class OpenIddictModule {
        /// <summary>
        /// Initializes a new OpenIddict module.
        /// </summary>
        /// <param name="name">The name of the module.</param>
        /// <param name="position">The position of the module in the ASP.NET Core pipeline.</param>
        /// <param name="registration">The delegate used to register the module in the pipeline.</param>
        public OpenIddictModule(
            [NotNull] string name, int position,
            [NotNull] Action<IApplicationBuilder> registration) {
            Name = name;
            Position = position;
            Registration = registration;
        }

        /// <summary>
        /// Initializes a new OpenIddict module.
        /// </summary>
        /// <param name="registration">The delegate used to register the module in the pipeline.</param>
        public OpenIddictModule([NotNull] Action<IApplicationBuilder> registration) {
            Registration = registration;
        }

        /// <summary>
        /// Gets or sets the name of the module.
        /// </summary>
        public string Name { get; }

        /// <summary>
        /// Gets or sets the position of the module in the ASP.NET Core pipeline.
        /// </summary>
        public int Position { get; }

        /// <summary>
        /// Gets or sets the delegate used to register the
        /// OpenIddict module in the ASP.NET Core pipeline.
        /// </summary>
        public Action<IApplicationBuilder> Registration { get; }
    }
}
