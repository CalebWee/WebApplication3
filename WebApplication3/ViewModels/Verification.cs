using System.ComponentModel.DataAnnotations;

namespace WebApplication3.ViewModels
{
	public class Verification
	{
        [Required]
        [DataType(DataType.EmailAddress)]
        public string Email { get; set; }
        [Required]
        public int OTP { get; set; }
    }
}
