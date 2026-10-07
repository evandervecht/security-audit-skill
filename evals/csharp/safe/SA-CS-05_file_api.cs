// SA-CS-06: Safe alternative using .NET file APIs instead of shell commands
using System.Text.RegularExpressions;

public class FileConverter
{
    private static readonly Regex SafeFilename = new(@"^[a-zA-Z0-9_\-]+\.(png|jpg|gif)$");

    public async Task<byte[]> ReadValidatedFile(string userFilename)
    {
        if (!SafeFilename.IsMatch(userFilename))
        {
            throw new ArgumentException("Invalid filename");
        }

        var basePath = Path.GetFullPath("/uploads");
        var fullPath = Path.GetFullPath(Path.Combine(basePath, userFilename));

        if (!fullPath.StartsWith(basePath + Path.DirectorySeparatorChar))
        {
            throw new SecurityException("Path traversal detected");
        }

        return await File.ReadAllBytesAsync(fullPath);
    }
}
