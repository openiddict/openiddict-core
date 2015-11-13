/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/core for more information concerning
 * the license and the contributors participating to this project.
 */

namespace OpenIddict.Models {
    public class Application {
        public string Id { get; set; }
        public string DisplayName { get; set; }
        public string RedirectUri { get; set; }
        public string LogoutRedirectUri { get; set; }
        public string Secret { get; set; }
        public string Type { get; set; }
    }
}