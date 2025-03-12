from rest_framework import serializers
from features.user.serializers import UserSerializer


class AuthTokenResponseSchema(serializers.Serializer):
    refresh = serializers.CharField()
    access = serializers.CharField()
    user = UserSerializer()
