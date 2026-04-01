// SA-DOTNET-05: Razor auto-encoding — safe output of user input
using Microsoft.AspNetCore.Mvc;

public class CommentsController : Controller
{
    [HttpGet]
    public IActionResult Show(string comment)
    {
        ViewBag.Comment = comment;
        return View();
    }
}

// In the associated Razor view (Comments/Show.cshtml):
// <div class="comment">
//     <p>@ViewBag.Comment</p>  <!-- Auto-encoded by Razor -->
// </div>
