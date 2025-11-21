from django.urls import path
from . import views

app_name = 'integrations'

urlpatterns = [
    path('', views.environment_list, name='list'),
    path('create/', views.environment_create, name='create'),
    path('<int:pk>/update/', views.environment_update, name='update'),
    path('<int:pk>/delete/', views.environment_delete, name='delete'),
]
