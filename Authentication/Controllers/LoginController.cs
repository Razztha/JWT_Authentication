using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.Identity.Client;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace Authentication.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class LoginController : ControllerBase
    {
        public LoginController(IConfiguration configuration)
        {
            _configuration = configuration;
        }

        private IConfiguration _configuration;

        [HttpPost]
        public IActionResult Login([FromBody] LoginModel loginModel)
        {
            if (ModelState.IsValid) 
            {
                if (loginModel.Username == "admin" && loginModel.Password == "111")
                {
                    var token = GenerateToken(loginModel.Username);

                    // store refresh token in the database with the expiration
                    var refreshToken = GenerateRefreshToken();

                    return Ok(new { AccessToken = new JwtSecurityTokenHandler().WriteToken(token)
                    , RefreshToken = refreshToken});
                }
            }

            return Unauthorized("Invalid credentials");
        }

        private string GenerateRefreshToken()
        {
            return Guid.NewGuid().ToString("N");
        }

        private JwtSecurityToken GenerateToken(string username)
        {
            var claims = new List<Claim>();
            {
                new Claim(ClaimTypes.Name, username);
            };

            var token = new JwtSecurityToken(
            issuer: _configuration["Jwt:Issuer"],
            audience: _configuration["Jwt:Audience"],
            claims:claims,
            expires:DateTime.Now.AddMinutes(2),
            signingCredentials: new SigningCredentials(new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["Jwt:Key"])),
                SecurityAlgorithms.HmacSha256)
            );

            return token;
        }

    }
}
