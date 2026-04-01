# SA-DJANGO-02: CSRF disabled via @csrf_exempt (VULNERABLE)
from django.views.decorators.csrf import csrf_exempt
from django.http import JsonResponse


@csrf_exempt
def transfer_funds(request):
    if request.method == "POST":
        amount = request.POST.get("amount")
        recipient = request.POST.get("recipient")
        return JsonResponse({"status": "ok"})
