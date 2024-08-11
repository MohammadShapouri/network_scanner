from django.urls import path
from . import views

urlpatterns = [
    path('create-session/', views.NetworkScanningSessionCreationView.as_view(), name='create-session'),
    path('update-session/<int:pk>', views.NetworkScanningSessionUpdateView.as_view(), name='update-session'),
    path('delete-session/<int:pk>', views.NetworkScanningSessionDeletionView.as_view(), name='delete-session'),
    path('list-session/', views.NetworkScanningSessionListView.as_view(), name='list-session'),
    path('session-detail/<int:pk>', views.NetworkScanningSessionDetailView.as_view(), name='session-detail'),
    path('session-device-detail/<int:pk>', views.NetworkScanningSessionDeviceDetailView.as_view(), name='session-device-detail'),
]