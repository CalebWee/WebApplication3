using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using WebApplication3.Model;

namespace WebApplication3.Pages
{
    [Authorize]
    public class PrivacyModel : PageModel
    {
        private readonly ILogger<PrivacyModel> _logger;
        private readonly SignInManager<ApplicationUser> signInManager;
        public PrivacyModel(ILogger<PrivacyModel> logger, SignInManager<ApplicationUser> signInManager)
        {
            _logger = logger;
            this.signInManager = signInManager;
        }

        public async Task<PageResult> OnGetAsync()
        {
            var cookieAuth = HttpContext.Request.Cookies["AuthToken"];
            var sessionAuth = HttpContext.Session.GetString("_token");
            var sessionLoggedIn = HttpContext.Session.GetString("_username");
            if (sessionLoggedIn != null && sessionAuth != null && cookieAuth != null)
            {
                if (sessionAuth.ToString().Equals(cookieAuth))
                {
                    return Page();
                }
            }
            else
            {
                HttpContext.Session.Clear();
                await signInManager.SignOutAsync();
                Response.Redirect("/Account/Login");
            }
            return Page();
        }
    }
}