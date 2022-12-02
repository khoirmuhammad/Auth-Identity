# Authentication Core Identity
In this section we will cover several functionalities provided by ASP NET Core Identity Such as
- User Registration
- Email Activation / Confirmation after registration
- Login Logout
- Forgot & Reset Password using email sending

Before proceeding the process, install the foloowing packages below
- Microsoft.EntityFrameworkCore.Tools (Database Migration Purpose)
- Microsoft.EntitiFrameworkCore.SqlServer (SQL Server Purpose)
- Microsoft.AspNetCore.Identity.EntityFrameworkCore (Auth Identity Purpose)
- AutoMapper.Extensions.Microsoft.DependencyInjection (Model Auto Mapper Purpose)
- NETCore.MailKit (Mail Purpose)

## User Registration

Storing data user in AspNetUsers table
```
await _userManager.CreateAsync(user, userModel.Password);
```
Mapping between User and Role in AspNetUserRoles table
```
await _userManager.AddToRoleAsync(user, "User");
```

## ** Email Service
https://code-maze.com/aspnetcore-send-email/  
http://help.warmupinbox.com/en/articles/4934806-configure-for-google-workplace-with-two-factor-authentication-2fa  

Follow above article to get email service in deep & how to configure gmail

```
"EmailConfiguration": {
    "MailFrom": "mk.muhammadkhoirudin@gmail.com",
    "SmtpServer": "smtp.gmail.com",
    "Port": 465,
    "Username": "mk.muhammadkhoirudin@gmail.com",
    "Password": "<secret password from 2FA not gmail account password>"
  }
```
Create EmailConfiguration Class that match with email config property in appsettings.json. We will mapping between JSON and Class. additionally we will inject the class in this step. So we able to use object mail configuration after creating instance in constructor
```
var emailConfig = builder.Configuration.GetSection("EmailConfiguration").Get<EmailConfiguration>();
builder.Services.AddSingleton(emailConfig);
```
## Email Activation / Confirmation
Once user stored into database, the logic need to be done is sending email
```
var token = await _userManager.GenerateEmailConfirmationTokenAsync(user); // token will validate that user performing activation is user that make registration
var confirmationLink = Url.Action(nameof(ConfirmEmail), "Account", new { token, email = user.Email }, Request.Scheme);
var message = new EmailMessage(new string[] { user.Email }, "Confirmation email link", confirmationLink);
await _emailSender.SendEmailAsync(message);
```

## Login
We will perform login in 2 ways i.e Manual Login and Auto Login
### Manual Login
In this way, we will :
- Check that user is exist & password is correct. 
- Check configuration need activation / confirmation or not. If it is, then need to read "EmailConfirmed" value from database
- After all of them is done. Then need to create claims

### Auto Login
```
var result = await _signInManager.PasswordSignInAsync
                (userModel.Email, userModel.Password, userModel.RememberMe, false);
```
We only need call the method and 3 steps in manual login will be done automatically. Please see https://code-maze.com/authentication-aspnet-core-identity/ in order need to create custom claims.

## Forgot & Reset Password
- In forgot password we only need to generate token. It will validate that user do reset password is trusted user
- In reset password we only need send new password, email and token

## ** Service Configuration Program.cs
In order to perform Model Mapping / Data Transfer Object if necessary
```
builder.Services.AddAutoMapper(typeof(Program));
```
Here we will injecting IdentityRole to User
- It will make validation that password should be at least 7 character, uppercase
- It will make the user should input unique email
- It will make that users need to activate / confirm their email after registration
- "AddDefaultTokenProviders()" it will make token generation when we use forget password and email activation token
```
builder.Services.AddIdentity<User, IdentityRole>(opt =>
{
    opt.Password.RequiredLength = 7;
    opt.Password.RequireDigit = true;
    opt.Password.RequireUppercase = true;

    opt.User.RequireUniqueEmail = true;
    opt.SignIn.RequireConfirmedEmail = true;
})
.AddEntityFrameworkStores<ApplicationContext>().AddDefaultTokenProviders();
```
It will make token in forget password will expire after 1 hour. in case we need to apply this expiration to email activation please see https://code-maze.com/email-confirmation-aspnet-core-identity/ to create custom token provider
```
builder.Services.Configure<DataProtectionTokenProviderOptions>(opt =>
   opt.TokenLifespan = TimeSpan.FromHours(1));
```
Cookie configuration
```
builder.Services.ConfigureApplicationCookie(options =>
    {
        options.Events.OnRedirectToLogin = (context) =>
        {
            context.Response.StatusCode = 401;
            return Task.CompletedTask;
        };

        options.Events.OnRedirectToAccessDenied = (context) =>
        {
            context.Response.StatusCode = 403;
            return Task.CompletedTask;
        };
    }
);
```
