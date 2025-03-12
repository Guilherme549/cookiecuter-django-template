from rest_framework_simplejwt import views
from features.authentication import serializers
from features.authentication import schemas
from drf_spectacular.utils import extend_schema


class TokenObtainPairView(views.TokenObtainPairView):
    serializer_class = serializers.TokenObtainPairSerializer

    @extend_schema(responses={"200": schemas.AuthTokenResponseSchema})
    def post(self, request, *args, **kwargs):
        return super().post(request, *args, **kwargs)


class TokenRefreshView(views.TokenRefreshView):
    pass
