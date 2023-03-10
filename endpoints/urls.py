from django.urls import path
from .views import RegisterUserAPIView, LoginViewAPIView, UserListAPIView, UserDetailsAPIView, RetrieveUserAPIView


urlpatterns = [
    path('api/register/', RegisterUserAPIView.as_view()),
    path('api/login/', LoginViewAPIView.as_view()),
    path('api/profile/', UserListAPIView.as_view()),
    path('api/users/<int:pk>/', UserDetailsAPIView.as_view()),
    path('api/users/<int:pk>/details/', RetrieveUserAPIView.as_view()),
]
