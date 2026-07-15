from django.urls import path

from . import poc_views, views

app_name = "submissions"

urlpatterns = [
    path("", views.submit, name="submit"),
    path("ranking/", views.leaderboard, name="leaderboard"),
    path("submissions/<int:pk>/", views.result, name="result"),
    path("api/submissions/<int:pk>/status", views.status_json, name="status_json"),
    path("api/submissions/<int:pk>/events", views.generation_events_json, name="events_json"),
    path("submissions/<int:pk>/rerun", views.rerun, name="rerun"),
    path("submissions/<int:pk>/poc/", poc_views.poc_console, name="poc_console"),
    path("submissions/<int:pk>/poc/start", poc_views.poc_start, name="poc_start"),
    path("submissions/<int:pk>/poc/run", poc_views.poc_run, name="poc_run"),
    path("submissions/<int:pk>/poc/stop", poc_views.poc_stop, name="poc_stop"),
]
