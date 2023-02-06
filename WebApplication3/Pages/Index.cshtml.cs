using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using System.Web;
using WebApplication3.Model;

namespace WebApplication3.Pages
{
    [Authorize]
    public class IndexModel : PageModel
    {
        public string BirthDate {get;set;}
        private readonly ILogger<IndexModel> _logger;
        private readonly SignInManager<ApplicationUser> signInManager;
        private readonly UserManager<ApplicationUser> userManager;
        public IndexModel(ILogger<IndexModel> logger, SignInManager<ApplicationUser> signInManager, UserManager<ApplicationUser> userManager)
        {
            _logger = logger;
            this.signInManager = signInManager;
            this.userManager = userManager;
        }
        public ApplicationUser MyUser { get; set; } = new();

        public async Task<PageResult> OnGetAsync()
        {
            var cookieAuth = HttpContext.Request.Cookies["AuthToken"];
            var sessionAuth = HttpContext.Session.GetString("_token");
            var sessionLoggedIn = HttpContext.Session.GetString("_username");
            if (sessionLoggedIn != null && sessionAuth != null && cookieAuth != null)
            {
                if (sessionAuth.ToString().Equals(cookieAuth))
                {
                    var dataProtectionProvider = DataProtectionProvider.Create("EncryptData");
                    var protector = dataProtectionProvider.CreateProtector("MySecretKey");
                    ApplicationUser user = userManager.Users.FirstOrDefault(x => x.UserName.Equals(sessionLoggedIn));
                    MyUser = user;
                    BirthDate = MyUser.DateOfBirth.ToString("MM/dd/yyyy");
                    MyUser.WhoamI = HttpUtility.HtmlDecode(MyUser.WhoamI);
                    MyUser.NRIC = protector.Unprotect(MyUser.NRIC);
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