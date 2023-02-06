using Microsoft.Extensions.Logging;
using Newtonsoft.Json.Serialization;
using System.ComponentModel.DataAnnotations;
using System.Diagnostics.Metrics;
using System.Text.RegularExpressions;

namespace WebApplication3.ViewModels
{
    public class Register
    {
        [Required]
        [DataType(DataType.Text)]
        public string FirstName { get; set; }

        [Required]
        [DataType(DataType.Text)]
        public string LastName { get; set; }

        [Required]
        [DataType(DataType.Text)]
        public string Gender { get; set; }

        [Required, RegularExpression(@"^[STFG]\d{7}[A-Z]$", ErrorMessage = "Invalid NRIC."), MaxLength(9)]
        [DataType(DataType.Text)]
        public string NRIC { get; set; }

        [Required]
        [DataType(DataType.EmailAddress)]
        public string Email { get; set; }

        [Required]
        [DataType(DataType.Password)]
        [RegularExpression(@"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[$@$!%*?&])[A-Za-z\d$@$!%*?&]{12,}$", ErrorMessage = "Passwords must be at least 12 characters long and uses a combination of lower-case, upper-case, Numbers and special characters")]
        public string Password { get; set; }

        [Required]
        [DataType(DataType.Password)]
        [Compare(nameof(Password), ErrorMessage = "Password and confirmation password does not match")]
        public string ConfirmPassword { get; set; }

        [Required]
        [DataType(DataType.Date)]
        public DateTime DateOfBirth { get; set; } = new DateTime(DateTime.Now.Year - 18, 1, 1);

        [Required]
        [DataType(DataType.Upload)]
        [RegularExpression(@"^([0-9a-zA-Z_\-~ :\\])+(.docx|.pdf)$", ErrorMessage = "Resume File Format must be in pdf or docx.")]
        public string Resume { get; set; }

        [Required]
        [DataType(DataType.Text)]
        [RegularExpression(@"^.{1,250}$")]
        public string WhoamI { get; set; }
        public string? Salt {get; set;}
        public int? OTP { get; set; } = 0;
        public DateTime? OTPValidTil { get; set; }
        public bool? VerifiedAcc { get; set; } 
        public string? PasswordHashed { get; set; }


    }
}
