# SA-DJANGO-01: Safe parameterized ORM query (SAFE)
from myapp.models import User


def search_users(request):
    query = request.GET.get("q")
    users = User.objects.filter(name=query)
    return render(request, "users.html", {"users": users})
