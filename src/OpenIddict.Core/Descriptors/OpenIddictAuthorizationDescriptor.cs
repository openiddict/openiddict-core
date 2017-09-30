using System.Collections.Generic;

namespace OpenIddict.Core
{
    /// <summary>
    /// Represents an OpenIddict authorization descriptor.
    /// </summary>
    public class OpenIddictAuthorizationDescriptor
    {
        /// <summary>
        /// Gets or sets the application identifier associated with the authorization.
        /// </summary>
        public string ApplicationId { get; set; }

        /// <summary>
        /// Gets or sets the scopes associated with the authorization.
        /// </summary>
        public IEnumerable<string> Scopes { get; set; }

        /// <summary>
        /// Gets or sets the status associated with the authorization.
        /// </summary>
        public string Status { get; set; }

        /// <summary>
        /// Gets or sets the subject associated with the authorization.
        /// </summary>
        public string Subject { get; set; }
    }
}
