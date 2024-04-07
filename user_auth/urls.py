from django.urls import path
from . import views
from django.contrib.auth import views as auth_views


urlpatterns = [
    
    path('', views.login, name="login"),
    path('signup', views.signup, name="signup"),
    path('profile', views.profile, name="profile"),
     path('logout', views.user_logout, name='logout'),

] 
