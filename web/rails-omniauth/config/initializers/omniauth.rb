require 'omniauth/strategies/openid_connect'

# Skip userinfo endpoint — extract claims from the ID token instead.
# The Vouch OIDC server includes email in the ID token.
OmniAuth::Strategies::OpenIDConnect.class_eval do
  private

  def user_info
    @user_info ||= begin
      decoded = decode_id_token(access_token.id_token).raw_attributes
      ::OpenIDConnect::ResponseObject::UserInfo.new(decoded)
    end
  end
end

Rails.application.config.middleware.use OmniAuth::Builder do
  provider :openid_connect,
    name: :vouch,
    issuer: ENV['VOUCH_ISSUER'] || 'https://us.vouch.sh',
    discovery: true,
    client_options: {
      identifier: ENV['VOUCH_CLIENT_ID'],
      secret: ENV['VOUCH_CLIENT_SECRET'],
      redirect_uri: ENV['VOUCH_REDIRECT_URI'] || 'http://localhost:3000/auth/vouch/callback'
    },
    scope: [:openid, :email]
end
