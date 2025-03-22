from django.urls import path
from .views import scan, report

urlpatterns = [
    path("", scan, name="scan"),
    path("report/<int:scan_id>/", report, name="report"),
]
