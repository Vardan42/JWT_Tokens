namespace JWT_Tokens.Models
{
    public class User
    {
        public string Name { get; set; } = string.Empty;

        public string PasswordHash { get; set; }=string.Empty;
    }
}
