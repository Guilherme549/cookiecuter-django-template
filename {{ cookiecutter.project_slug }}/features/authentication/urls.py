from django.urls import path
from features.authentication import views

urlpatterns = [
    path("token/", views.TokenObtainPairView.as_view(), name="token_obtain"),
    path("token/refresh/", views.TokenRefreshView.as_view(), name="token_refresh"),
]
