from django.conf import settings
from django.contrib import admin
from django.urls import path, include, reverse
from django.conf.urls.static import static
from django.shortcuts import redirect

urlpatterns = [
    path("admin/", admin.site.urls),
    path("api/", include("core.api.urls")),
    path("", lambda x: redirect(reverse("swagger-ui"))),
]

if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
