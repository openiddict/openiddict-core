using System.Collections.Generic;
using OpenIddict;

namespace Microsoft.AspNet.Builder {
    /// <summary>
    /// Holds various properties allowing to configure OpenIddct.
    /// </summary>
    public class OpenIddictBuilder {
        /// <summary>
        /// Gets the list of the OpenIddict modules.
        /// </summary>
        public ICollection<OpenIddictModule> Modules { get; } = new List<OpenIddictModule>();

        /// <summary>
        /// Gets or sets the options used by OpenIddict.
        /// </summary>
        public OpenIddictOptions Options { get; set; } = new OpenIddictOptions();
    }
}
