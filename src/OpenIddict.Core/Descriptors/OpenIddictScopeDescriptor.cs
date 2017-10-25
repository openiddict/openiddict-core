namespace OpenIddict.Core
{
    /// <summary>
    /// Represents an OpenIddict scope descriptor.
    /// </summary>
    public class OpenIddictScopeDescriptor
    {
        /// <summary>
        /// Gets or sets the description
        /// associated with the scope.
        /// </summary>
        public virtual string Description { get; set; }

        /// <summary>
        /// Gets or sets the unique name
        /// associated with the scope.
        /// </summary>
        public virtual string Name { get; set; }
    }
}
