from django.urls import path

from . import views

app_name = "submissions"

urlpatterns = [
    path("", views.submit, name="submit"),
    path("ranking/", views.leaderboard, name="leaderboard"),
    path("submissions/<int:pk>/", views.result, name="result"),
    path("api/submissions/<int:pk>/status", views.status_json, name="status_json"),
    path("api/submissions/<int:pk>/events", views.generation_events_json, name="events_json"),
    path("submissions/<int:pk>/rerun", views.rerun, name="rerun"),
]
