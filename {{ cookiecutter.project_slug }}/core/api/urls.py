from django.urls import path, include, reverse
from django.shortcuts import redirect

urlpatterns = [
    path("health/", include("core.api.health.urls")),
    path("auth/", include("features.authentication.urls")),
    path("docs/", include("core.swagger.urls")),
    path("users/", include("features.user.urls")),
    path("", lambda x: redirect(reverse("swagger-ui"))),
]
