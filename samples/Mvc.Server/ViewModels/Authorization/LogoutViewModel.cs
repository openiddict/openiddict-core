using System.Collections.Generic;
using Microsoft.AspNetCore.Mvc.ModelBinding;

namespace Mvc.Server.ViewModels.Authorization {
    public class LogoutViewModel {
        [BindNever]
        public IDictionary<string, string> Parameters { get; set; }
    }
}
