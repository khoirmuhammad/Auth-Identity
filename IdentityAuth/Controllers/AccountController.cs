using AutoMapper;
using IdentityAuth.Email;
using IdentityAuth.Models;
using IdentityAuth.Models.CustomModels;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.EntityFrameworkCore;
using System.Security.Claims;
using System.Transactions;

namespace IdentityAuth.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AccountController : ControllerBase
    {
        private readonly IMapper _mapper;
        private readonly UserManager<User> _userManager;
        private readonly SignInManager<User> _signInManager;
        private readonly IEmailSender _emailSender;
        public AccountController(
            IMapper mapper, 
            UserManager<User> userManager, 
            SignInManager<User> signInManager,
            IEmailSender emailSender)
        {
            _mapper = mapper;
            _userManager = userManager;
            _signInManager = signInManager;
            _emailSender = emailSender;
        }

        [HttpPost]
        [Route("Register")]
        public async Task<IActionResult> Register([FromBody] UserRegistrationModel userModel)
        {
            ApiResponseModel response = new ApiResponseModel();

            var user = _mapper.Map<User>(userModel);
            var result = await _userManager.CreateAsync(user, userModel.Password);

            if (!result.Succeeded)
            {
                response.Code = BadRequest().StatusCode;
                response.ErrorMessages = result.Errors.Select(s => s.Description).ToList();

                return BadRequest(response);
            }

            await _userManager.AddToRoleAsync(user, "User");

            var token = await _userManager.GenerateEmailConfirmationTokenAsync(user);

            var param = new Dictionary<string, string?>
            {
                {"token", token },
                {"email", user.Email }
            };

            var callback = QueryHelpers.AddQueryString(userModel.ClientURI, param);
            //var confirmationLink = Url.Action(nameof(ConfirmEmail), "Account", new { token, email = user.Email }, Request.Scheme);
            var message = new EmailMessage(new string[] { user.Email }, "Confirmation email link", callback);
            await _emailSender.SendEmailAsync(message);
           

            return StatusCode(201, userModel);
        }

        [HttpGet]
        [Route("ConfirmEmail")]
        public async Task<IActionResult> ConfirmEmail(string token, string email)
        {
            ApiResponseModel response = new ApiResponseModel();

            var user = await _userManager.FindByEmailAsync(email);

            if (user == null)
            {
                response.Code = NotFound().StatusCode;
                response.ErrorMessages.Add($"{email} was not found.");

                return NotFound(response);
            }

            if (user.EmailConfirmed)
            {
                response.Code = BadRequest().StatusCode;
                response.ErrorMessages.Add("Email has confirmed");

                return BadRequest(response);
            }

            var result = await _userManager.ConfirmEmailAsync(user, token);

            if (!result.Succeeded)
            {
                response.Code = BadRequest().StatusCode;
                response.ErrorMessages.Add("Invalid Email Confirmation Request");

                return BadRequest(response);
            }

            response.Code = Ok().StatusCode;
            response.ErrorMessages.Add("Successfully");

            return Ok(response);
        }

        [HttpPost]
        [Route("Login")]
        public async Task<IActionResult> Login([FromBody] UserLoginModel userModel)
        {
            ApiResponseModel response = new ApiResponseModel();

            User? user = await _userManager.FindByEmailAsync(userModel.Email);
            bool isPasswordValid = await _userManager.CheckPasswordAsync(user, userModel.Password);

            bool isRequiredConfirmedEmailInConfig = _userManager.Options.SignIn.RequireConfirmedEmail;
            bool isEmailConfirmed = isRequiredConfirmedEmailInConfig ? await _userManager.IsEmailConfirmedAsync(user) : true;          

            if (user != null && isPasswordValid)
            {
                if (isEmailConfirmed)
                {
                    var identity = new ClaimsIdentity(IdentityConstants.ApplicationScheme);

                    identity.AddClaim(new Claim(ClaimTypes.NameIdentifier, user.Id));
                    identity.AddClaim(new Claim(ClaimTypes.Name, user.UserName));

                    await HttpContext.SignInAsync(IdentityConstants.ApplicationScheme,
                        new ClaimsPrincipal(identity));

                    return Ok();
                }
                else
                {
                    response.Code = BadRequest().StatusCode;
                    response.ErrorMessages.Add("Confirm your email first after registering");

                    return BadRequest(response);
                }
                
            }
            else
            {
                response.Code = BadRequest().StatusCode;
                response.ErrorMessages.Add("Check your email & password before attemping login");

                return BadRequest();
            }
        }

        [HttpPost]
        [Route("AutoLogin")]
        public async Task<IActionResult> AutoLogin([FromBody] UserLoginModel userModel)
        {
            ApiResponseModel response = new ApiResponseModel();

            var result = await _signInManager.PasswordSignInAsync
                (userModel.Email, userModel.Password, userModel.RememberMe, lockoutOnFailure: true);

            if (result.Succeeded)
            {
                return Ok();
            }

            if (result.IsLockedOut)
            {
                var forgotPassLink = Url.Action(nameof(ForgotPassword), "Account", new { }, Request.Scheme);
                var content = string.Format("Your account is locked out, to reset your password, please click this link: {0}", forgotPassLink);
                var message = new EmailMessage(new string[] { userModel.Email }, "Locked out account information", content);
                await _emailSender.SendEmailAsync(message);

                response.Code = Ok().StatusCode;
                response.ErrorMessages.Add("Your account is locked out, Please check email");

                return Ok(response);
            }
            else
            {
                response.Code = BadRequest().StatusCode;
                response.ErrorMessages.Add("Please verify your account");

                return BadRequest(response);
            }

        }

        [HttpPost]
        [Route("ForgotPassword")]
        public async Task<IActionResult> ForgotPassword([FromBody]ForgotPasswordModel forgotPasswordModel)
        {
            ApiResponseModel response = new ApiResponseModel();

            var user = await _userManager.FindByEmailAsync(forgotPasswordModel.Email);
            if (user == null)
            {
                response.Code = NotFound().StatusCode;
                response.ErrorMessages.Add($"{forgotPasswordModel?.Email} is not found.");

                return NotFound(response);
            }

            var token = await _userManager.GeneratePasswordResetTokenAsync(user);
            
            var message = new EmailMessage(new string[] { user.Email }, "Reset password token", token);
            await _emailSender.SendEmailAsync(message);

            return Ok();
        }

        [HttpPost]
        [Route("ResetPassword")]
        public async Task<IActionResult> ResetPassword([FromBody] ResetPasswordModel resetPasswordModel)
        {
            ApiResponseModel response = new ApiResponseModel();

            var user = await _userManager.FindByEmailAsync(resetPasswordModel.Email);
            if (user == null)
            {
                response.Code = NotFound().StatusCode;
                response.ErrorMessages.Add($"{resetPasswordModel?.Email} is not found.");

                return NotFound(response);
            }

            var resetPassResult = await _userManager.ResetPasswordAsync(
                user, resetPasswordModel.Token, resetPasswordModel.Password);

            if (resetPassResult.Succeeded)
            {
                return Ok();
            }
            else
            {
                response.Code = BadRequest().StatusCode;
                response.ErrorMessages = resetPassResult.Errors.Select(s => s.Description).ToList();

                return BadRequest();
            }
        }

        [Authorize]
        [HttpPost]
        [Route("Logout")]
        public async Task<IActionResult> Logout()
        {
            await _signInManager.SignOutAsync();
            return Ok();
        }
    }
}
