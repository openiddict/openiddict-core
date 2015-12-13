using System;
using Microsoft.AspNet.Builder;

namespace OpenIddict {
    /// <summary>
    /// Defines an OpenIddict module.
    /// </summary>
    public class OpenIddictModule {
        /// <summary>
        /// Gets or sets the name of the module.
        /// </summary>
        public string Name { get; set; }

        /// <summary>
        /// Gets or sets the position of the module in the ASP.NET pipeline.
        /// </summary>
        public int Position { get; set; }

        /// <summary>
        /// Gets or sets the delegate used to register
        /// the OpenIddict module in the ASP.NET pipeline.
        /// </summary>
        public Action<IApplicationBuilder> Registration { get; set; }
    }
}
