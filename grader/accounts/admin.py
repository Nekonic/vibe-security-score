"""Operator admin: rebuilds UserAdmin fieldsets without the removed email field."""
from django.contrib import admin
from django.contrib.auth.admin import UserAdmin

from .models import Operator


@admin.register(Operator)
class OperatorAdmin(UserAdmin):
    fieldsets = (
        (None, {"fields": ("username", "password")}),
        ("이름", {"fields": ("first_name", "last_name")}),
        ("권한", {"fields": ("is_active", "is_staff", "is_superuser", "groups", "user_permissions")}),
        ("주요 일시", {"fields": ("last_login", "date_joined")}),
    )
    add_fieldsets = (
        (None, {"classes": ("wide",), "fields": ("username", "password1", "password2")}),
    )
    list_display = ("username", "is_staff", "is_superuser", "last_login")
    ordering = ("username",)
