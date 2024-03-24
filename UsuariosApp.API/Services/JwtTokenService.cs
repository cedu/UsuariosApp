using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using UsuariosApp.API.Identity.Entities;
using UsuariosApp.API.Settings;

namespace UsuariosApp.API.Services
{
    /// <summary>
    /// Classe de serviço para geração dos TOKENS JWT
    /// </summary>
    public class JwtTokenService
    {
        private readonly JwtTokenSettings _jwtTokenSettings;

        public JwtTokenService(JwtTokenSettings jwtTokenSettings)
        {
            _jwtTokenSettings = jwtTokenSettings;
        }

        /// <summary>
        /// Método para criar e retornar um TOKEN JWT para um usuário
        /// </summary>
        public string CreateToken(Usuario usuario)
        {
            var expiration = DateTime.UtcNow.AddHours(int.Parse(_jwtTokenSettings.ExpirationInHours));
            var token = CreateJwtToken(
                CreateClaims(usuario),
                CreateSigningCredentials(),
                expiration
            );
            var tokenHandler = new JwtSecurityTokenHandler();
            return tokenHandler.WriteToken(token);
        }

        private JwtSecurityToken CreateJwtToken(List<Claim> claims, SigningCredentials credentials, DateTime expiration) =>
            new(
                _jwtTokenSettings.Issuer,
                _jwtTokenSettings.Audience,
                claims,
                expires: expiration,
                signingCredentials: credentials
            );

        private List<Claim> CreateClaims(Usuario usuario)
        {
            var jwtSub = _jwtTokenSettings.JwtClaimNamesSub;
            try
            {
                var claims = new List<Claim>
            {
                new Claim(JwtRegisteredClaimNames.Sub, jwtSub),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                new Claim(JwtRegisteredClaimNames.Iat, DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString()),
                new Claim(ClaimTypes.NameIdentifier, usuario.Id),
                new Claim(ClaimTypes.Name, usuario.UserName),
                new Claim(ClaimTypes.Email, usuario.Email),
            };

                return claims;
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
                throw;
            }
        }

        private SigningCredentials CreateSigningCredentials()
        {
            var symmetricSecurityKey = _jwtTokenSettings.SecurityKey;

            return new SigningCredentials(
                new SymmetricSecurityKey(
                    Encoding.UTF8.GetBytes(symmetricSecurityKey)
                ),
                SecurityAlgorithms.HmacSha256
            );
        }
    }
}