using System.ComponentModel.DataAnnotations;

namespace Autenticacao.Api.Models
{
    public class RegistrarUsuarioModel
    {
        [Required]
        public string Nome { get; set; }

        [Required]
        [EmailAddress(ErrorMessage = "E-mail inválido.")]
        public string Email { get; set; }

        [Required]
        [DataType(DataType.Password)]
        public string Senha { get; set; }

        [DataType(DataType.Password)]
        [Display(Name = "Confirmar Senha")]
        [Compare("Senha", ErrorMessage = "Senhas diferentes")]
        public string ConfirmaSenha { get; set; }
    }
}
