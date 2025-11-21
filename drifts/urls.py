from django.urls import path
from . import views

app_name = 'drifts'

urlpatterns = [
    path('', views.drift_list, name='list'),
    path('<int:pk>/', views.drift_detail, name='detail'),
    path('<int:pk>/remediate/', views.remediate_drift, name='remediate'),
    path('scan/', views.scan_infrastructure, name='scan'),
]
