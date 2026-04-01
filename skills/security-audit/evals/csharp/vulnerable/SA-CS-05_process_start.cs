// SA-CS-06: Command injection via Process.Start
using System.Diagnostics;

public class FileConverter
{
    public void Convert(string userFilename)
    {
        Process.Start("cmd.exe", $"/c convert {userFilename} output.pdf");
    }
}
