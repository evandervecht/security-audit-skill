# SA-DJANGO-04: XSS via mark_safe() with user input (VULNERABLE)
from django.utils.safestring import mark_safe


def user_profile(request, user_id):
    user = User.objects.get(id=user_id)
    bio_html = mark_safe(user.bio)
    return render(request, "profile.html", {"bio": bio_html})
