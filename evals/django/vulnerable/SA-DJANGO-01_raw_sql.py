# SA-DJANGO-01: ORM injection via raw() with f-string (VULNERABLE)
from myapp.models import User


def search_users(request):
    query = request.GET.get("q")
    users = User.objects.raw(f"SELECT * FROM myapp_user WHERE name = '{query}'")
    return render(request, "users.html", {"users": users})
