namespace OpenIddict.Core
{
    /// <summary>
    /// Represents an OpenIddict application descriptor.
    /// </summary>
    public class OpenIddictApplicationDescriptor
    {
        /// <summary>
        /// Gets or sets the client identifier
        /// associated with the application.
        /// </summary>
        public virtual string ClientId { get; set; }

        /// <summary>
        /// Gets or sets the client secret associated with the application.
        /// Note: depending on the application manager used when creating it,
        /// this property may be hashed or encrypted for security reasons.
        /// </summary>
        public virtual string ClientSecret { get; set; }

        /// <summary>
        /// Gets or sets the display name
        /// associated with the application.
        /// </summary>
        public virtual string DisplayName { get; set; }

        /// <summary>
        /// Gets or sets the logout callback URL
        /// associated with the application.
        /// </summary>
        public virtual string LogoutRedirectUri { get; set; }

        /// <summary>
        /// Gets or sets the callback URL
        /// associated with the application.
        /// </summary>
        public virtual string RedirectUri { get; set; }

        /// <summary>
        /// Gets or sets the application type
        /// associated with the application.
        /// </summary>
        public virtual string Type { get; set; }
    }
}
