namespace IdentityAuth.Email
{
    public interface IEmailSender
    {
        void SendEmail(EmailMessage message);
        Task SendEmailAsync(EmailMessage message);
    }
}
