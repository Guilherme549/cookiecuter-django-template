from django.contrib.auth.models import update_last_login
from django.utils.module_loading import import_string
from rest_framework_simplejwt import serializers
from rest_framework_simplejwt.settings import api_settings


class TokenObtainPairSerializer(serializers.TokenObtainPairSerializer):
    user_serializer_class = None
    _user_serializer_class = "features.user.serializers.UserSerializer"

    def get_user_serializer_class(self):
        """
        If user_serializer_class is set, use it directly. Otherwise get the class from _user_serializer_class.
        """
        if self.user_serializer_class:
            return self.user_serializer_class
        try:
            return import_string(self._user_serializer_class)
        except ImportError:
            msg = "Could not import serializer '%s'" % self._user_serializer_class
            raise ImportError(msg)

    def validate(self, attrs):
        data = super().validate(attrs)

        refresh = self.get_token(self.user)
        user_serializer_class = self.get_user_serializer_class()
        user_serializer = user_serializer_class(self.user)

        data["refresh"] = str(refresh)
        data["access"] = str(refresh.access_token)
        data["user"] = user_serializer.data

        if api_settings.UPDATE_LAST_LOGIN:
            update_last_login(None, self.user)

        return data
