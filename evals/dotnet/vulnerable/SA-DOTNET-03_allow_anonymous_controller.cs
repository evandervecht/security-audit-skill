// SA-DOTNET-03: [AllowAnonymous] on entire controller class
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

[ApiController]
[Route("api/[controller]")]
[AllowAnonymous]
public class UsersController : ControllerBase
{
    [HttpGet]
    public IActionResult GetAll() => Ok("public list");

    [HttpDelete("{id}")]
    public IActionResult Delete(int id) => NoContent();

    [HttpPut("{id}/role")]
    public IActionResult ChangeRole(int id, [FromBody] string role) => Ok();
}
