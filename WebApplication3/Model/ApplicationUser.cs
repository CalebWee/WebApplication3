using Microsoft.AspNetCore.Identity;

namespace WebApplication3.Model
{
    public class ApplicationUser:IdentityUser
    {
        public string FirstName { get; set; }
        public string LastName { get; set; }
        public string Gender { get; set; }
        public string NRIC { get; set; } 
        public DateTime DateOfBirth { get; set; }
        public string Resume { get; set; }
        public string WhoamI { get; set; }
        public string Salt { get; set; }
        public string PasswordHashed { get; set; }
        public int OTP { get; set; }
        public bool VerifiedAcc { get; set; }
        public DateTime OTPValidTil {get; set; }

    }
}
