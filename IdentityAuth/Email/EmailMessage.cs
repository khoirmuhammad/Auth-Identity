using MimeKit;
using System.Net.Mail;

namespace IdentityAuth.Email
{
    public class EmailMessage
    {
        public List<MailboxAddress> MailTo { get; set; }
        public string Subject { get; set; }
        public string? Content { get; set; }
        public EmailMessage(IEnumerable<string> mailTo, string subject, string? content)
        {
            MailTo = new List<MailboxAddress>();

            foreach(string to in mailTo) 
            {
                MailTo.Add(MailboxAddress.Parse(to));
            }

            Subject = subject;
            Content = content;

        }
    }
}
