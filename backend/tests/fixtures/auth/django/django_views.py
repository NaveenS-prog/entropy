"""Django fixture demonstrating function and class-based views with auth patterns."""

from django.contrib.auth.decorators import login_required, permission_required
from django.http import JsonResponse
from rest_framework import viewsets
from rest_framework.permissions import IsAuthenticated, IsAdminUser


# Clean authenticated function view
@login_required
def user_account_view(request):
    return JsonResponse({"user": request.user.username})


# Clean authenticated and authorized function view
@login_required
@permission_required("admin.change_user")
def admin_manage_view(request):
    return JsonResponse({"managed": True})


# Clean DRF ViewSet with auth & authz
class SecureAdminViewSet(viewsets.ModelViewSet):
    permission_classes = [IsAuthenticated, IsAdminUser]

    def get(self, request):
        return JsonResponse({"data": []})


# Unprotected sensitive CBV missing permission classes
class UnprotectedAdminViewSet(viewsets.ModelViewSet):
    permission_classes = []

    def delete(self, request):
        return JsonResponse({"deleted": True})
