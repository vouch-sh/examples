from django.contrib import admin
from django.urls import path, include
from views import home

urlpatterns = [
    path('', home, name='home'),
    path('accounts/', include('allauth.urls')),
    path('admin/', admin.site.urls),
]
