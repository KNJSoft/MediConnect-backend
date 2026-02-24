# pharmacy_app/permissions.py
from rest_framework import permissions
from .models import UserRole

class IsSuperAdmin(permissions.BasePermission):
    """
    Allows access only to SuperAdmin users.
    """
    def has_permission(self, request, view):
        return request.user and request.user.is_authenticated and request.user.role == UserRole.SUPER_ADMIN

class IsAdmin(permissions.BasePermission):
    """
    Allows access only to CompanyAdmin users.
    """
    def has_permission(self, request, view):
        return request.user and request.user.is_authenticated and request.user.role == UserRole.ADMIN

class IsDoctor(permissions.BasePermission):
    """
    Allows access only to CompanyAdmin users.
    """
    def has_permission(self, request, view):
        return request.user and request.user.is_authenticated and request.user.role == UserRole.DOCTOR

class IsPatient(permissions.BasePermission):
    """
    Allows access only to Patient users.
    """
    def has_permission(self, request, view):
        return request.user and request.user.is_authenticated and request.user.role == UserRole.PATIENT

class IsSelfOrAdmin(permissions.BasePermission):
    """
    Allows access only to the user themselves or to SuperAdmin/CompanyAdmin/AgencyAdmin.
    """
    def has_object_permission(self, request, view, obj):
        # Allow read-only access for anyone authenticated
        if request.method in permissions.SAFE_METHODS:
            return True

        # Allow full access if the user is a SuperAdmin, CompanyAdmin, or AgencyAdmin
        if request.user.role in [UserRole.SUPER_ADMIN, UserRole.DOCTOR,UserRole.ADMIN]:
            return True

        # Allow access only if the user is the owner of the object
        return obj == request.user

# admin or super admin

class IsAdminOrSuperAdmin(permissions.BasePermission):
    def has_permission(self, request, view):
        return request.user and request.user.is_authenticated and request.user.role in [UserRole.SUPER_ADMIN, UserRole.ADMIN]
    
    def has_object_permission(self, request, view, obj):
        return request.user and request.user.is_authenticated and request.user.role in [UserRole.SUPER_ADMIN, UserRole.ADMIN]

# doctor or super admin

class IsDoctorOrSuperAdmin(permissions.BasePermission):
    def has_permission(self, request, view):
        return request.user and request.user.is_authenticated and request.user.role in [UserRole.SUPER_ADMIN, UserRole.DOCTOR]
    
    def has_object_permission(self, request, view, obj):
        return request.user and request.user.is_authenticated and request.user.role in [UserRole.SUPER_ADMIN, UserRole.DOCTOR]

# doctor or admin or super admin

class IsDoctorOrAdminOrSuperAdmin(permissions.BasePermission):
    def has_permission(self, request, view):
        return request.user and request.user.is_authenticated and request.user.role in [UserRole.SUPER_ADMIN, UserRole.DOCTOR, UserRole.ADMIN]
    
    def has_object_permission(self, request, view, obj):
        return request.user and request.user.is_authenticated and request.user.role in [UserRole.SUPER_ADMIN, UserRole.DOCTOR, UserRole.ADMIN]
    

#  all

class IsAll(permissions.BasePermission):
    def has_permission(self, request, view):
        return request.user and request.user.is_authenticated
    
    def has_object_permission(self, request, view, obj):
        return request.user and request.user.is_authenticated
        