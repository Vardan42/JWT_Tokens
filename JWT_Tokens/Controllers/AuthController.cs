using JWT_Tokens.Models;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace JWT_Tokens.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        public static User  user=new User();
        private readonly IConfiguration   configuration;
        public AuthController(IConfiguration configuration)
        {
            this.configuration = configuration;
        }
        [HttpPost]
        public ActionResult<User> Register(UserDto request)
        {

            string passwordHash=BCrypt.Net.BCrypt.HashPassword(request.Password);

            user.Name = request.Username;
            user.PasswordHash=passwordHash;
            return Ok(user);
        }
        [HttpPost("Login")]
        public ActionResult<User> Login(UserDto request)
        {
            if (user.Name==request.Username)
            {
                return BadRequest();
            }
            if (!BCrypt.Net.BCrypt.Verify(request.Password,user.PasswordHash))
            {
                return BadRequest();
            }
            string token = CreateToken(user);
            return Ok(token);
        }
        private string CreateToken(User user)
        {
            List<Claim> claims = new List<Claim>()
            {
                new Claim(ClaimTypes.Name,user.Name),

            };

            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(
                configuration.GetSection("AppSettings:Token").Value
                )) ;

            var cred = new SigningCredentials(key, SecurityAlgorithms.HmacSha512Signature);

            var token = new JwtSecurityToken(
                claims:claims,
                expires:DateTime.Now.AddDays(1),
                signingCredentials:cred
                );
            var jwt=new JwtSecurityTokenHandler().WriteToken(token);
            return jwt;
        
        }
    }
}
