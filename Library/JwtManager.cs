using AuthenticateZeroServer.Models;

using Microsoft.IdentityModel.Tokens;

using System;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;

namespace AuthenticateZeroServer {
    public static class JwtManager {
        private const string Secret = "your-very-long-secret-key-here";

        public static string GenerateToken(IUser user) {
            var symmetricKey = Convert.FromBase64String(Secret);
            var tokenHandler = new JwtSecurityTokenHandler();

            var now = DateTime.UtcNow;
            var tokenDescriptor = new SecurityTokenDescriptor {
                Subject = new ClaimsIdentity(new[]
                        {
                            new Claim("id", user.Id.ToString()),
                            new Claim("login", user.Login),
                            new Claim(ClaimTypes.Email, user.Email),
                            new Claim(ClaimTypes.Name, user.Name),
                            new Claim(ClaimTypes.Surname, user.Surname)
                            // add more here...
                        }),

                Expires = now.AddDays(7),

                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(symmetricKey), SecurityAlgorithms.HmacSha512Signature)
            };

            SecurityToken securityToken = tokenHandler.CreateToken(tokenDescriptor);
            var token = tokenHandler.WriteToken(securityToken);

            return token;
        }

        public static ClaimsPrincipal GetPrincipal(string token) {
            try {
                var tokenHandler = new JwtSecurityTokenHandler();

                if (!(tokenHandler.ReadToken(token) is JwtSecurityToken jwtToken)) {
                    return null;
                }

                var symmetricKey = Convert.FromBase64String(Secret);

                var validationParameters = new TokenValidationParameters() {
                    RequireExpirationTime = true,
                    ValidateIssuer = false,
                    ValidateAudience = false,
                    IssuerSigningKey = new SymmetricSecurityKey(symmetricKey)
                };

                var principal = tokenHandler.ValidateToken(token, validationParameters, out _);

                return principal;
            }

            catch (Exception) {
                return null;
            }
        }
    }
}
