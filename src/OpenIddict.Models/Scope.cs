namespace OpenIddict.Models {
    public class Scope {
        public string ScopeID { get; set; }
        public string DisplayName { get; set; }
        public string Description { get; set; }

        public string ApplicationID { get; set; }
        public Application Application { get; set; }
    }
}