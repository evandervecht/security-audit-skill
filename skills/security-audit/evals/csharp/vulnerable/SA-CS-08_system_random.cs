// SA-CS-10: Insecure random using System.Random
public class TokenGenerator
{
    private readonly Random _random = new Random();

    public string GenerateSessionToken()
    {
        var bytes = new byte[32];
        _random.NextBytes(bytes);
        return Convert.ToBase64String(bytes);
    }
}
