from rest_framework.permissions import BasePermission


class IsBusinessOrSuperAdmin(BasePermission):

    def has_permission(self, request, view):
        user = request.user
        if not user.is_authenticated:
            return False
        return user.groups.filter(name='business').exists() or user.is_superuser
