// SA-DOTNET-01: Wrong middleware ordering — auth after routing
using Microsoft.AspNetCore.Builder;

public class Program
{
    public static void Main(string[] args)
    {
        var builder = WebApplication.CreateBuilder(args);
        builder.Services.AddControllers();
        builder.Services.AddAuthentication();
        builder.Services.AddAuthorization();

        var app = builder.Build();

        app.UseRouting();
        app.MapControllers();
        app.UseAuthentication();
        app.UseAuthorization();
        app.Run();
    }
}
