from django.urls import path
from .views import RegisterUserAPIView,LoginViewAPIView,UserProfileAPIView,UserDetailsAPIView
urlpatterns = [
  path('api/register/',RegisterUserAPIView.as_view()),
  path('api/login/', LoginViewAPIView.as_view()),
  path('api/profile/', UserProfileAPIView.as_view()),
  path('api/users/<int:pk>/', UserDetailsAPIView.as_view()),
]