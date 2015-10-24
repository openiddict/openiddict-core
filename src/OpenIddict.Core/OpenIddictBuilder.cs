using OpenIddict;

namespace Microsoft.AspNet.Builder {
    /// <summary>
    /// Holds various properties allowing to configure OpenIddct.
    /// </summary>
    public class OpenIddictBuilder : OpenIdConnectServerBuilder {
        public OpenIddictBuilder(IApplicationBuilder builder)
            : base(builder) {
            Options = new OpenIddictOptions();
        }

        /// <summary>
        /// Gets or sets the options used by OpenIddict.
        /// </summary>
        public new OpenIddictOptions Options {
            get { return base.Options as OpenIddictOptions; }
            set { base.Options = value; }
        }
    }
}
