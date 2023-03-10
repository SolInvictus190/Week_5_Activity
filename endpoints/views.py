from rest_framework.permissions import AllowAny

from .serializers import RegisterSerializer,LoginSerializer,UserSerializer
from rest_framework import generics, status
from rest_framework.permissions import IsAuthenticated
from django.contrib.auth.models import User
from django.http import Http404
from rest_framework.response import Response
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.views import APIView


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

class UserDetailsAPIView(APIView):
    permission_classes = (IsAuthenticated,)

    def get_user(self, pk):
        try:
            return User.objects.get(pk=pk)
        except User.DoesNotExist:
            raise Http404

    def get(self, request, pk):
        user = self.get_user(pk)

        if user == request.user:
            serializer = UserSerializer(user)
        else:
            serializer = UserSerializer(user, fields=('last_name', 'profile_picture'))

        return Response(serializer.data)

    def put(self, request, pk):
        user = self.get_user(pk)

        if user != request.user:
            return Response({'detail': 'You do not have permission to perform this action.'}, status=status.HTTP_403_FORBIDDEN)

        serializer = UserSerializer(user, data=request.data, partial=True)

        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        else:
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def patch(self, request, pk):
        return self.put(request, pk)

class UserProfileAPIView(APIView):
    permission_classes = (IsAuthenticated,)

    def get(self, request, user_id=None):
        if user_id is None:
            user = request.user
            serializer = UserSerializer(user)
            return Response(serializer.data)
        else:
            try:
                user = User.objects.get(id=user_id)
                serializer = UserSerializer(user, fields=('id', 'last_name'))
                return Response(serializer.data)
            except User.DoesNotExist:
                raise Http404