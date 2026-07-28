# frozen_string_literal: true

require 'json/jwt'
require 'net/http'

# Verifies Vouch access tokens against the issuer's published JWKS.
#
# hardware_verified is only in the access token, not the id_token. The access token is
# an ES256-signed RFC 9068 JWT, so verify it rather than decoding the payload -- an
# unverified decode trusts whatever bytes you were handed.
#
# Uses json-jwt, which omniauth_openid_connect already depends on.
module AccessTokenVerifier
  ISSUER = ENV.fetch('VOUCH_ISSUER', 'https://us.vouch.sh')
  CLIENT_ID = ENV['VOUCH_CLIENT_ID']

  class VerificationError < StandardError; end

  class << self
    def verify(token)
      raise VerificationError, 'no access token' if token.blank?

      # RFC 9068 access tokens carry typ: at+jwt. Requiring it rejects id_tokens,
      # which are not bearer credentials.
      header = JSON::JWT.decode(token, :skip_verification).header
      unless header[:typ].to_s.casecmp('at+jwt').zero?
        raise VerificationError, "unexpected typ: #{header[:typ]}"
      end

      claims = JSON::JWT.decode(token, jwks)

      raise VerificationError, 'issuer mismatch' unless claims[:iss] == ISSUER
      raise VerificationError, 'audience mismatch' unless Array(claims[:aud]).include?(CLIENT_ID)
      raise VerificationError, 'token expired' if claims[:exp] && Time.at(claims[:exp]) < Time.now

      claims
    end

    private

    # Refetched per call to keep the example short. A real app should cache this and
    # only refetch when it encounters an unknown `kid`.
    def jwks
      JSON::JWK::Set.new(JSON.parse(Net::HTTP.get(URI("#{ISSUER}/oauth/jwks"))))
    end
  end
end
