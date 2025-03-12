from rest_framework import serializers, exceptions
from django.contrib.auth.hashers import make_password
from features.user import models


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = models.User
        exclude = [
            "password",
            "is_superuser",
            "is_staff",
            "groups",
            "user_permissions",
        ]


class ChangeUserPasswordSerializer(serializers.Serializer):
    password1 = serializers.CharField()
    password2 = serializers.CharField()

    def validate_password2(self, value):
        if value != self.initial_data.get("password1"):
            raise exceptions.ValidationError("As duas senhas não batem")
        return value

    def save(self, **kwargs):
        request = self.context.get("request")
        user = request.user
        validated_data = self.validated_data

        user.password = make_password(validated_data.get("password1"))
        user.update_password = False
        user.save()

        return user


class UserForgotPasswordSerializer(serializers.Serializer):
    email = serializers.EmailField()
    
    def validate_email(self, value):
        account = models.User.objects.filter(email=value)
        
        if not account.exists():
            raise serializers.ValidationError(
                f"O email {value} não possui conta ativa"
            )
        
        self.user = account.first()
        
        return value
    
    def save(self, **kwargs):
        models.UserForgotPasswordToken.objects.create(
            usuario=self.user,
            token=uuid4() # add in models default ?
        )
        
        
class UserForgotSetPasswordSerializer(serializers.Serializer):
    user = serializers.HiddenField(default=serializers.CurrentUserDefault())
    password1 = serializers.CharField()
    password2 = serializers.CharField()

    def validate_password2(self, value):
        password1 = self.initial_data.get("password1")
        if not value == password1:
            raise serializers.ValidationError("As senhas não são iguais.")

        return value
    
    def save(self, **kwargs):
        user = self.validated_data.get("user")
        password = self.validated_data.get("password1")

        user.password = make_password(password)
        user.save()