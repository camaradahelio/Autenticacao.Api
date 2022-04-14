using System.ComponentModel.DataAnnotations;

namespace Autenticacao.Api.Models
{
    public class LoginModel
    {
        [Required]
        [EmailAddress(ErrorMessage = "E-mail com formato incorreto!")]
        public string Email { get; set; }

        [Required]
        [DataType(DataType.Password)]
        public string Senha { get; set; }
    }
}
