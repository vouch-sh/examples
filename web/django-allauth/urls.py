from django.contrib import admin
from django.urls import include, path
from views import home, oidc_callback

urlpatterns = [
    path("", home, name="home"),
    # Listed ahead of allauth.urls so it takes the same path as allauth's own
    # callback; allauth still builds the redirect_uri from its URL name.
    path("accounts/oidc/<str:provider_id>/login/callback/", oidc_callback),
    path("accounts/", include("allauth.urls")),
    path("admin/", admin.site.urls),
]
