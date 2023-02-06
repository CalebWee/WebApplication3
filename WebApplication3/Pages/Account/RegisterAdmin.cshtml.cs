using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using System.Security.Cryptography;
using System.Text;
using System.Web;
using WebApplication3.Model;
using WebApplication3.ViewModels;
using SendGrid;
using SendGrid.Helpers.Mail;

namespace WebApplication3.Pages.Account
{
    public class RegisterAdminModel : PageModel
    {
        private UserManager<ApplicationUser> userManager { get; }
        private SignInManager<ApplicationUser> signInManager { get; }
        private RoleManager<IdentityRole> roleManager { get; }
        static string finalHash;
        static string salt;
        byte[] Key;
        byte[] IV;


        [BindProperty]
        public Register RModel { get; set; }

        public RegisterAdminModel(UserManager<ApplicationUser> userManager,
        SignInManager<ApplicationUser> signInManager,
        RoleManager<IdentityRole> roleManager)
        {
            this.userManager = userManager;
            this.signInManager = signInManager;
            this.roleManager = roleManager;
        }


        public void OnGet()
        {
        }


        public async Task<IActionResult> OnPostAsync()
        {
            if (ModelState.IsValid)
            {
                IdentityRole role = await roleManager.FindByIdAsync("Admin");
                if (role == null)
                {
                    IdentityResult result2 = await roleManager.CreateAsync(new IdentityRole("Admin"));
                }
                var dataProtectionProvider = DataProtectionProvider.Create("EncryptData");
                var protector = dataProtectionProvider.CreateProtector("MySecretKey");
                try
                {
                    if (userManager.Users.Any(k => k.Email.ToLower() == RModel.Email.ToLower()))
                    {
                        ModelState.AddModelError("Danger", "Email has already been registered. Please enter another valid email.");
                    }
                    if (RModel.DateOfBirth > DateTime.Now)
                    {
                        ModelState.AddModelError("Danger", "Invalid Date of Birth.");
                    }
                    else
                    {
                        string pwd = RModel.Password.Trim();
                        RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider();
                        byte[] saltByte = new byte[8];
                        rng.GetBytes(saltByte);
                        salt = Convert.ToBase64String(saltByte);
                        SHA512Managed hashing = new SHA512Managed();
                        string pwdWithSalt = pwd + salt;
                        byte[] plainHash = hashing.ComputeHash(Encoding.UTF8.GetBytes(pwd));
                        byte[] hashWithSalt = hashing.ComputeHash(Encoding.UTF8.GetBytes(pwdWithSalt));
                        finalHash = Convert.ToBase64String(hashWithSalt);
                        RModel.Salt = salt;
                        RModel.PasswordHashed = finalHash;
                        RModel.Password = finalHash;
                        RijndaelManaged cipher = new RijndaelManaged();
                        cipher.GenerateKey();
                        Key = cipher.Key;
                        IV = cipher.IV;
                        Random random = new Random();
                        int number = random.Next(100000, 1000000);

                        var user = new ApplicationUser()
                        {
                            UserName = HttpUtility.HtmlEncode(RModel.Email),
                            FirstName = HttpUtility.HtmlEncode(RModel.FirstName),
                            LastName = HttpUtility.HtmlEncode(RModel.LastName),
                            Gender = HttpUtility.HtmlEncode(RModel.Gender),
                            Email = HttpUtility.HtmlEncode(RModel.Email),
                            NRIC = protector.Protect(HttpUtility.HtmlEncode(RModel.NRIC)),
                            DateOfBirth = RModel.DateOfBirth,
                            Resume = HttpUtility.HtmlEncode(RModel.Resume),
                            WhoamI = HttpUtility.HtmlEncode(RModel.WhoamI),
                            Salt = RModel.Salt,
                            PasswordHashed = RModel.PasswordHashed,
                            OTP = number,
                            OTPValidTil = DateTime.Now.AddMinutes(10),
                            VerifiedAcc = false
                        };

                        var result = await userManager.CreateAsync(user, RModel.Password);
                        if (result.Succeeded)
                        {
                            var apiKey = "Hello";
                            var client = new SendGridClient(apiKey);
                            var msg = new SendGridMessage()
                            {
                                From = new EmailAddress("cactuswee04@gmail.com", "AceJobAgency"),
                                Subject = "Verifying Ace Job Agency Account",
                                PlainTextContent = "Your otp is " + user.OTP
                            };
                            msg.AddTo(new EmailAddress(RModel.Email, RModel.FirstName));
                            var response = await client.SendEmailAsync(msg);
                            result = await userManager.AddToRoleAsync(user, "Admin");
                            return RedirectToPage("/account/verificationotp");
                        }
                        foreach (var error in result.Errors)
                        {
                            ModelState.AddModelError("", error.Description);
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
