from django.contrib import admin
from django.contrib.auth.decorators import login_not_required
from django.contrib.auth.views import LoginView, LogoutView
from django.urls import include, path

urlpatterns = [
    # The login page is the ONLY unauthenticated view (no signup exists).
    path(
        "login/",
        login_not_required(
            LoginView.as_view(
                template_name="registration/login.html",
                redirect_authenticated_user=True,
            )
        ),
        name="login",
    ),
    path("logout/", LogoutView.as_view(), name="logout"),
    path("admin/", admin.site.urls),
    path("", include("submissions.urls")),
]
