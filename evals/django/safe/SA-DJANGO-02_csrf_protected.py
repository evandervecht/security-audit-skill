# SA-DJANGO-02: CSRF-protected view using default middleware (SAFE)
from django.http import JsonResponse


def transfer_funds(request):
    if request.method == "POST":
        amount = request.POST.get("amount")
        recipient = request.POST.get("recipient")
        return JsonResponse({"status": "ok"})
