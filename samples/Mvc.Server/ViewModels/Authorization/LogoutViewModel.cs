using Microsoft.AspNetCore.Mvc.ModelBinding;

namespace Mvc.Server.ViewModels.Authorization {
    public class LogoutViewModel {
        [BindNever]
        public string RequestId { get; set; }
    }
}
