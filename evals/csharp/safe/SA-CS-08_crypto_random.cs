// SA-CS-10: Secure random using RandomNumberGenerator
using System.Security.Cryptography;

public class TokenGenerator
{
    public string GenerateSessionToken()
    {
        var bytes = RandomNumberGenerator.GetBytes(32);
        return Convert.ToHexString(bytes);
    }
}
