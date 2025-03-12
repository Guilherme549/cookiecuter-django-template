from rest_framework import views, status, response
from features.user import serializers, models
from drf_spectacular.utils import extend_schema, OpenApiResponse

class AuthenticatedUserAPIView(views.APIView):
    @extend_schema(
        responses={
            200: serializers.UserSerializer,
        },
        description="Obtem os dados do usuário logado",
    )
    def get(self, request):
        serializer = serializers.UserSerializer(instance=request.user, context={'request':request})
        return response.Response(serializer.data, status=status.HTTP_200_OK)


class ChangeUserPasswordAPIView(views.APIView):
    @extend_schema(
        responses={200: OpenApiResponse({}, description="Senha alterada com sucesso")},
        description="Altera a senha do usuário logado",
        request=serializers.ChangeUserPasswordSerializer,
    )
    def put(self, request):
        serializer = serializers.ChangeUserPasswordSerializer(
            data=request.data,
            context={
                "request": request,
            },
        )
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return response.Response()
    

class UserForgotPasswordAPIView(views.APIView):
    def post(self, request, token=None):
        return self.change_password(request, token) or self.send_token(request)
            
    def change_password(self, request, token):
        if not token:
            return
        
        token = models.UserForgotPasswordToken.objects.filter(token=token)

        if not token.exists():
            return response.Response("O Token informado não existe")
        
        token = token.first()        
        
        if not token.is_valid():
            return response.Response("O Token informado não é mais válido")
        
        request.user = token.usuario.user
        
        serializer = serializers.UserForgotSetPasswordSerializer(
            data=request.data,
            context={"request": request}
        )
        serializer.is_valid(raise_exception=True)
        serializer.save()
        
        token.delete()
        
        return response.Response("A senha foi alterada com sucesso")
    
        
    def send_token(self, request):
        serializer = serializers.UserForgotPasswordSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        
        return response.Response("Token enviado", status=200)
