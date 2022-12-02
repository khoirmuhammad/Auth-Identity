using System.ComponentModel.DataAnnotations;

namespace IdentityAuth.Models.CustomModels
{
    public class ForgotPasswordModel
    {
        [Required]
        [EmailAddress]
        public string Email { get; set; } = string.Empty;
    }
}
