using Microsoft.AspNetCore.Identity;

namespace Autenticacao.Api.Models
{
    public class ValidacaoModel 
    {
        public string Mensagem { get; internal set; }
        public string[] Detalhes { get; internal set; } = new string[] { };

        public ValidacaoModel(string mensagem, string[] detalhes)
        {
            Mensagem = mensagem;
            Detalhes = detalhes;
        }

    }
}
