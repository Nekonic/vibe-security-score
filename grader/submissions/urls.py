from django.urls import path

from . import operator_views, preview_views, views

app_name = "submissions"

urlpatterns = [
    path("", views.submit, name="submit"),
    path("ranking/", views.leaderboard, name="leaderboard"),
    path("submissions/<int:pk>/", views.result, name="result"),
    path("api/submissions/<int:pk>/status", views.status_json, name="status_json"),
    path("api/submissions/<int:pk>/events", views.generation_events_json, name="events_json"),
    path("submissions/<int:pk>/rerun", views.rerun, name="rerun"),
    path("submissions/<int:pk>/code/", operator_views.code_view, name="code_view"),
    path("submissions/<int:pk>/kali/", operator_views.kali_console, name="kali_console"),
    path("submissions/<int:pk>/kali/start", operator_views.kali_start, name="kali_start"),
    path("submissions/<int:pk>/kali/io", operator_views.kali_io, name="kali_io"),
    path("submissions/<int:pk>/kali/stop", operator_views.kali_stop, name="kali_stop"),
    path("submissions/<int:pk>/app/", preview_views.app_proxy, name="app_preview"),
    path("submissions/<int:pk>/app/<path:subpath>", preview_views.app_proxy),
]
