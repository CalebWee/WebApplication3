using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using System.Net;
using System.Text.Encodings.Web;
using WebApplication3.Core;
using WebApplication3.Model;
using WebApplication3.ViewModels;
using System.Security.Cryptography;
using System.Text;
using System.Data;
using System.Data.SqlClient;
using System.Web;

namespace WebApplication3.Pages.Account
{
    public class LoginModel : PageModel
    {
        private UserManager<ApplicationUser> userManager { get; }
        private readonly GoogleCaptchaService _captchaService;
        [BindProperty]
        public Login LModel { get; set; }

        private readonly SignInManager<ApplicationUser> signInManager;
        public LoginModel(SignInManager<ApplicationUser> signInManager, GoogleCaptchaService captchaService, UserManager<ApplicationUser> userManager)
        {
            this.signInManager = signInManager;
            _captchaService = captchaService;
            this.userManager = userManager;
        }
        public void OnGet()
        {
        }

        public async Task<IActionResult> OnPostAsync()
        {
            var captchaResult = await _captchaService.VerifyToken(LModel.Token);
            if (!captchaResult)
            {
                ModelState.AddModelError("Danger", "Failed the captcha");
            }
            else if (ModelState.IsValid)
            {
                string pwd = HttpUtility.HtmlEncode(LModel.Password);
                string userid = HttpUtility.HtmlEncode(LModel.Email);
                SHA512Managed hashing = new SHA512Managed();
                ApplicationUser user = userManager.Users.FirstOrDefault(x => x.UserName.Equals(userid));
                if(user == null)
                {
                    ModelState.AddModelError("Danger", "Username or password is wrong");
                }
                else if (user.VerifiedAcc == true)
                {
                    string dbHash = user.PasswordHashed;
                    string dbSalt = user.Salt;
                    try
                    {
                        if (dbSalt != null && dbSalt.Length > 0 && dbHash != null && dbHash.Length > 0)
                        {
                            string pwdWithSalt = pwd + dbSalt;
                            byte[] hashWithSalt = hashing.ComputeHash(Encoding.UTF8.GetBytes(pwdWithSalt));
                            string userHash = Convert.ToBase64String(hashWithSalt);
                            LModel.Password = userHash;
                            var identityResult = await signInManager.PasswordSignInAsync(HttpUtility.HtmlEncode(LModel.Email), HttpUtility.HtmlEncode(LModel.Password),
                    LModel.RememberMe, true);
                            if (identityResult.Succeeded)
                            {
                                string guid = Guid.NewGuid().ToString();
                                HttpContext.Session.SetString("_username", user.Email);
                                HttpContext.Session.SetString("_token", guid);
                                HttpContext.Response.Cookies.Append("AuthToken", guid);
                                Response.Redirect("/index");
                            }
                            if (identityResult.IsLockedOut)
                            {

                                ModelState.AddModelError("Danger", "Exceeded 3 attempts. Account lockout for 5 minutes.");
                            }
                            else
                            {
                                ModelState.AddModelError("Danger", "Username or password is wrong");
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
                else
                {
                    ModelState.AddModelError("Danger", "Account is unverified");
                }

            }
            return Page();
        }



    }
}
