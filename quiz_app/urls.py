from django.urls import path
from . import views

urlpatterns = [
    path('', views.landing_page, name='landing'),
    path('quiz/', views.quiz_page, name='quiz'),
    path('result/', views.result_page, name='result'),
     path('send-otp/', views.send_otp, name='send_otp'),
      path('login/', views.login_view, name='login'),
    path('logout/', views.logout_view, name='logout'),
     path("register/", views.register, name="register"),
]
