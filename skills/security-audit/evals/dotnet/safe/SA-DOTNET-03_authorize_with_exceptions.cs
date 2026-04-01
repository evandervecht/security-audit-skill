// SA-DOTNET-03: Controller-level Authorize with targeted AllowAnonymous
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

[ApiController]
[Route("api/[controller]")]
[Authorize]
public class UsersController : ControllerBase
{
    [HttpGet]
    [AllowAnonymous]
    public IActionResult GetAll() => Ok("public list");

    [HttpDelete("{id}")]
    [Authorize(Roles = "Admin")]
    public IActionResult Delete(int id) => NoContent();

    [HttpPut("{id}/role")]
    [Authorize(Policy = "SuperAdmin")]
    public IActionResult ChangeRole(int id, [FromBody] string role) => Ok();
}
