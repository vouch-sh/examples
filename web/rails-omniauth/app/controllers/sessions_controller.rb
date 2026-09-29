class SessionsController < ApplicationController
  def index
    render inline: <<~HTML
      <!DOCTYPE html>
      <html>
      <head><title>Vouch + Rails</title></head>
      <body>
        <h1>Vouch OIDC + Rails + OmniAuth</h1>
        <% if current_user %>
          <p>Signed in as <%= current_user['email'] %></p>
          <% if current_user['hardware_verified'] %>
            <p><strong>Hardware Verified</strong></p>
          <% end %>
          <ul>
            <li>email: <%= current_user['email'] %></li>
            <li>email_verified: <%= current_user['email_verified'] %></li>
            <li>sub: <%= current_user['sub'] %></li>
            <li>amr: <%= current_user['amr'].presence&.join(', ') || 'N/A' %></li>
            <li>acr: <%= current_user['acr'] || 'N/A' %></li>
            <li>hardware_verified: <%= current_user['hardware_verified'] %></li>
          </ul>
          <%= button_to 'Sign out', '/logout', method: :delete %>
        <% else %>
          <%= button_to 'Sign in with Vouch', '/auth/vouch', data: { turbo: false } %>
        <% end %>
      </body>
      </html>
    HTML
  end

  def create
    auth = request.env['omniauth.auth']

    # hardware_verified is only in the access token, not the id_token. The access token
    # is an ES256-signed RFC 9068 JWT, so verify it rather than decoding the payload --
    # an unverified decode trusts whatever bytes you were handed.
    claims = AccessTokenVerifier.verify(auth.credentials&.token)

    # raw_info merges the UserInfo response with the ID token claims the strategy has
    # already verified; sub, email_verified, acr and amr come from the ID token.
    id_claims = auth.extra.raw_info

    session[:user] = {
      'email' => auth.info.email,
      'email_verified' => id_claims['email_verified'] || false,
      'sub' => id_claims['sub'],
      'acr' => id_claims['acr'],
      'amr' => id_claims['amr'] || [],
      'hardware_verified' => claims['hardware_verified'] || false
    }
    # Kept for RP-initiated logout: Vouch only honours post_logout_redirect_uri when a
    # verified id_token_hint identifies the client.
    session[:id_token] = auth.credentials.id_token
    redirect_to root_path
  end

  def failure
    redirect_to root_path, alert: params[:message]
  end

  # Sign out locally, then at Vouch (OIDC RP-Initiated Logout 1.0). Clearing only the
  # local session leaves the user signed in at Vouch, so the next sign-in would
  # complete silently. Vouch shows a confirmation page and redirects back only when
  # id_token_hint verifies and post_logout_redirect_uri is registered on the client.
  #
  # omniauth_openid_connect has a built-in logout path, but it sends only
  # post_logout_redirect_uri -- never id_token_hint -- so Vouch would never redirect
  # back. The URL is built here instead, from the same discovery document.
  def destroy
    id_token = session[:id_token]
    reset_session

    end_session = OpenIDConnect::Discovery::Provider::Config
                  .discover!(AccessTokenVerifier::ISSUER).end_session_endpoint
    return redirect_to root_path if end_session.blank? || id_token.blank?

    query = URI.encode_www_form(
      id_token_hint: id_token,
      post_logout_redirect_uri: root_url,
      client_id: AccessTokenVerifier::CLIENT_ID
    )
    redirect_to "#{end_session}?#{query}", allow_other_host: true
  end
end
