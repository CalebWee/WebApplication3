using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using WebApplication3.Model;

namespace WebApplication3.Pages.Account
{
    [Authorize]
    public class LogoutModel : PageModel
    {
        private readonly SignInManager<ApplicationUser> signInManager;
        public LogoutModel(SignInManager<ApplicationUser> signInManager)
        {
            this.signInManager = signInManager;
        }
        public void OnGet()
        {
        }

        public async Task<IActionResult> OnPostLogoutAsync()
        {
            try
            {
                HttpContext.Session.Clear();
                await signInManager.SignOutAsync();
                return RedirectToPage("Login");
            }
            catch (Exception ex)
            {
                throw new Exception("Message = " + ex.Message + "<br>");
                throw new Exception("Source = " + ex.Source + "<br>");
                throw new Exception("Stack Trace = " + ex.StackTrace + "<br>");
                throw new Exception("TargetSite = " + ex.TargetSite + "<br>");
            }
        }
        public async Task<IActionResult> OnPostDontLogoutAsync()
        {
            return RedirectToPage("Index");
        }

    }
}
