from adapters import VouchOIDCAdapter
from allauth.socialaccount.models import SocialAccount
from allauth.socialaccount.providers.oauth2.views import OAuth2CallbackView
from django.shortcuts import render


def home(request):
    context = {}
    if request.user.is_authenticated:
        account = SocialAccount.objects.filter(user=request.user, provider='vouch').first()
        # The ID token claims VouchOIDCAdapter verified at sign-in (signature, iss, aud, exp).
        id_claims = account.extra_data.get('id_token', {}) if account else {}
        context['claims'] = {
            'email': id_claims.get('email'),
            'email_verified': id_claims.get('email_verified', False),
            'sub': id_claims.get('sub'),
            'amr': ', '.join(id_claims.get('amr', [])) or 'N/A',
            'acr': id_claims.get('acr') or 'N/A',
            'hardware_verified': request.session.get('vouch_hardware_verified', False),
        }
    return render(request, 'home.html', context)


def oidc_callback(request, provider_id):
    """allauth's own OpenID Connect callback view, run with VouchOIDCAdapter."""
    view = OAuth2CallbackView.adapter_view(VouchOIDCAdapter(request, provider_id))
    return view(request)
