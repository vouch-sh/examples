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
