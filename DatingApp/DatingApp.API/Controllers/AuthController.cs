using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Threading.Tasks;
using DatingApp.API.Data;
using DatingApp.API.Dtos;
using DatingApp.API.Model;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System.Security.Claims;

namespace DatingApp.API.Controllers
{
    [Route("api/[controller]")]
    
    public class AuthController : Controller
    {
        private readonly IAuthRepository _repo;
        public AuthController(IAuthRepository repo)
        {
            _repo = repo;

        }

        [HttpPost("register")]
        public async Task<IActionResult> Register([FromBody]UsersForRegisterDto usersForRegisterDto)
        {
            usersForRegisterDto.UserName = usersForRegisterDto.UserName.ToLower();
            if(await _repo.UserExisted(usersForRegisterDto.UserName))
                ModelState.AddModelError("UserName", "UserName already existed");

            if(!ModelState.IsValid) return BadRequest(ModelState);
            //validate request
           
            
            var userToCreate = new User
            {
                Username = usersForRegisterDto.UserName
            };

            var createUser = await _repo.Register(userToCreate, usersForRegisterDto.Password);

            return StatusCode(201);
           
        }

        [HttpPost("Login")]
        public async Task<IActionResult> Login([FromBody] UserForLoginDto userForLoginDto)
        {
            var userFromRepo = _repo.Login(userForLoginDto.UserName.ToLower(), userForLoginDto.Password);
            if(userFromRepo == null){
                return Unauthorized();
            }

            //generate token
            var tokenHandler = new JwtSecurityTokenHandler();
            var key = System.Text.Encoding.ASCII.GetBytes("super sceret key");
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(new Claim[]
                {
                    new Claim(ClaimTypes.NameIdentifier, userFromRepo.Id.ToString()),
                    new Claim(ClaimTypes.NameIdentifier, userFromRepo.Id.ToString())
                }),
                Expires = DateTime.Now.AddDays(1),
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key),
                            SecurityAlgorithms.HmacSha512Signature)  
            };
            var token = tokenHandler.CreateToken(tokenDescriptor);
            var tokenString = tokenHandler.WriteToken(token);
            return Ok(new {tokenString});
        }
    }
}