using Autenticacao.Api.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.ModelBinding;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace Autenticacao.Api.Controllers
{
    [ApiController]
    [AllowAnonymous]
    [Route("api/conta")]
    public class ContaController : ControllerBase
    {
        private readonly SignInManager<IdentityUser> _signInManager;
        private readonly UserManager<IdentityUser> _userManager;
        private readonly JwtSettings _jwtSettings;

        public ContaController(SignInManager<IdentityUser> signInManager, UserManager<IdentityUser> userManager, IOptions<JwtSettings> jwtSettings)
        {
            _signInManager = signInManager;
            _userManager = userManager;
            _jwtSettings = jwtSettings.Value;
        }

        private IActionResult IsInvalidModelStateResponse(ModelStateDictionary modelState)
        {
            string mensagem = "Erro na passagem de parâmetros.";
            var detalhes = modelState.Values.SelectMany(e => e.Errors.Select(x => x.ErrorMessage)).ToArray();
            ValidacaoModel validacao = new ValidacaoModel(mensagem, detalhes);
            return BadRequest(validacao);
        }

        private IActionResult IsInvalidCreateUser(IEnumerable<IdentityError> errors)
        {
            string mensagem = "Erro ao tentar criar usuário";
            var detalhes = errors.Select(e => e.Description).ToArray();
            ValidacaoModel validacaoModel = new ValidacaoModel(mensagem, detalhes);
            return BadRequest(validacaoModel);
        }

        [HttpPost]
        [Route("registrar")]
        [ApiConventionMethod(typeof(DefaultApiConventions), nameof(DefaultApiConventions.Post))]

        public async Task<IActionResult> Registrar(RegistrarUsuarioModel usuarioModel)
        {
            if (!ModelState.IsValid) return IsInvalidModelStateResponse(ModelState);

            var user = new IdentityUser
            {
                Email = usuarioModel.Email,
                UserName = usuarioModel.Email,
                EmailConfirmed = true
            };

            var result = await _userManager.CreateAsync(user, usuarioModel.Senha);

            if (result.Succeeded)
            {
                return Ok(await GerarJwtToken(usuarioModel.Email));
            }

            return IsInvalidCreateUser(result.Errors);

        }

        [HttpPost]
        [Route("entrar")]
        [ApiConventionMethod(typeof(DefaultApiConventions), nameof(DefaultApiConventions.Post))]

        public async Task<IActionResult> Login(LoginModel model)
        {
            if (!ModelState.IsValid) return IsInvalidModelStateResponse(ModelState);

            var result = await _signInManager.PasswordSignInAsync(model.Email, model.Senha, false, true);

            if (result.Succeeded)
            {
                return Ok(await GerarJwtToken(model.Email));
            }
            else if (result.IsLockedOut)
            {
                return Unauthorized(new ValidacaoModel("Usuário temporariamente bloqueado!", new string[] { }));
            }
            else
            {
                return BadRequest(new ValidacaoModel("Não foi possivel efeturar login, dados incorretos!", new string[] { }));
            }
        }

        private async Task<string> GerarJwtToken(string email)
        {
            var usuario = await _userManager.FindByEmailAsync(email);
            var claims = await _userManager.GetClaimsAsync(usuario);
            var roles = await _userManager.GetRolesAsync(usuario);

            claims.Add(new Claim(JwtRegisteredClaimNames.Sub, usuario.Id));
            claims.Add(new Claim(JwtRegisteredClaimNames.Email, usuario.Email));
            claims.Add(new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()));

            foreach (var role in roles)
            {
                claims.Add(new Claim("role", role));
            }

            var identityClaims = new ClaimsIdentity();
            identityClaims.AddClaims(claims);

            var tokenHandler = new JwtSecurityTokenHandler();

            var chave = Encoding.ASCII.GetBytes(_jwtSettings.Chave);

            var token = tokenHandler.CreateEncodedJwt(new SecurityTokenDescriptor
            {
                Issuer = _jwtSettings.Emissor,
                Audience = _jwtSettings.ValidoEm,
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(chave), SecurityAlgorithms.HmacSha256Signature),
                Subject = identityClaims,
                Expires = DateTime.UtcNow.AddHours(_jwtSettings.ExpiracaoEmHoras)
            });

            return token;
        }
    }
}
