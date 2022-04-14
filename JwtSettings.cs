namespace Autenticacao.Api
{
    public class JwtSettings
    {
        public string Chave { get; set; }
        public string ValidoEm { get; set; }

        public string Emissor { get; set; }
        public int ExpiracaoEmHoras { get; set; }
    }
}
