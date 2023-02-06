using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using SendGrid.Helpers.Mail;
using SendGrid;
using System.Security.Cryptography;
using System.Text;
using System.Web;
using WebApplication3.Model;
using WebApplication3.ViewModels;

namespace WebApplication3.Pages.Account
{
    public class VerificationOtpModel : PageModel
    {

        private UserManager<ApplicationUser> userManager { get; }
        private SignInManager<ApplicationUser> signInManager { get; }


        [BindProperty]
        public Verification VModel { get; set; }

        public VerificationOtpModel(UserManager<ApplicationUser> userManager,
        SignInManager<ApplicationUser> signInManager)
        {
            this.userManager = userManager;
            this.signInManager = signInManager;
        }


        public void OnGet()
        {
        }


        public async Task<IActionResult> OnPostAsync()
        {
            if (ModelState.IsValid)
            {
                try
                {
                    ApplicationUser user = userManager.Users.FirstOrDefault(x => x.UserName.Equals(VModel.Email));
                    if(user == null)
                    {
                        ModelState.AddModelError("Danger", "Email is not registered.");
                    }
                    else if(user.OTPValidTil < DateTime.Now)
                    {
                        ModelState.AddModelError("Danger", "OTP is invalid.");
                    }
                    else if(user.EmailConfirmed == true)
                    {
                        ModelState.AddModelError("Danger", "Email already verified");
                    }
                    else
                    {
                        if(VModel.OTP == user.OTP)
                        {
                            user.VerifiedAcc = true;
                            await userManager.UpdateAsync(user);
                            return RedirectToPage("/account/login");
                        }
                        else
                        {
                            ModelState.AddModelError("Danger", "OTP is wrong");
                        }
                    }
                    

                }
                catch (Exception ex)
                {
                    throw new Exception("Message = " + ex.Message + "<br>");
                    throw new Exception("Source = " + ex.Source + "<br>");
                    throw new Exception("Stack Trace = " + ex.StackTrace + "<br>");
                    throw new Exception("TargetSite = " + ex.TargetSite + "<br>");
                }
            }
            return Page();
        }

    }
}
