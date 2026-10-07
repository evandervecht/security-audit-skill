// SA-DOTNET-05: Overly permissive CORS policy
using Microsoft.AspNetCore.Builder;

public class Startup
{
    public void Configure(IApplicationBuilder app)
    {
        app.UseCors(builder => builder.AllowAnyOrigin().AllowAnyMethod().AllowAnyHeader());
    }
}
