from django.urls import path
from . import views

app_name = 'chat'

urlpatterns = [
    path('message/', views.chat_message, name='message'),
]
