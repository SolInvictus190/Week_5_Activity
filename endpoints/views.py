from rest_framework.permissions import AllowAny
from rest_framework.views import APIView
from .serializers import RegisterSerializer,LoginSerializer
from rest_framework import generics
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from django.contrib.auth.models import User
from django.http import Http404
from rest_framework.response import Response
from rest_framework_simplejwt.tokens import RefreshToken

class LoginViewAPIView(APIView):
    serializer_class = LoginSerializer

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.validated_data['user']
        refresh = RefreshToken.for_user(user)

        data = {
            'refresh': str(refresh),
            'access': str(refresh.access_token),
        }
        return Response(data=data, status=status.HTTP_200_OK)


class RegisterUserAPIView(generics.CreateAPIView):
    permission_classes = (AllowAny,)
    serializer_class = RegisterSerializer

    def perform_create(self, serializer):
        user = serializer.save()
        refresh = RefreshToken.for_user(user)

        data = {
            'refresh': str(refresh),
            'access': str(refresh.access_token),
        }
        serializer.validated_data['tokens'] = data

class UserProfileAPIView(APIView):
  permission_classes = (IsAuthenticated,)
  def get(self, request):
    try:
      user = request.user
      data = {
        'first_name': user.first_name,
        'last_name': user.last_name,
      }
      return Response(data)
    except User.DoesNotExist:
      raise Http404