from django.contrib import admin
from django.urls import path, include

urlpatterns = [
    path('admin/', admin.site.urls),
    path('core/', include(('core.urls', 'core'), namespace='core')),
    path('accounts/', include(('accounts.urls', 'accounts'), namespace='accounts')),
    path('', include(('dashboard.urls', 'dashboard'), namespace='dashboard')),
    path('drifts/', include(('drifts.urls', 'drifts'), namespace='drifts')),
    path('chat/', include(('chat.urls', 'chat'), namespace='chat')),
    path('integrations/', include(('integrations.urls', 'integrations'), namespace='integrations')),
]
