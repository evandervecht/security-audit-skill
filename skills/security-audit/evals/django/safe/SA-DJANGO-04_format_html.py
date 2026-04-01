# SA-DJANGO-04: Safe HTML construction with format_html (SAFE)
from django.utils.html import format_html


def greeting(request):
    name = request.GET.get("name", "World")
    message = format_html("<h1>Hello, {}!</h1>", name)
    return render(request, "greeting.html", {"message": message})
