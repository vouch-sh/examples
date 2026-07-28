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

    session[:user] = {
      'email' => auth.info.email,
      'hardware_verified' => claims['hardware_verified'] || false,
      'acr' => claims['acr'],
      'amr' => claims['amr'] || []
    }
    redirect_to root_path
  end

  def failure
    redirect_to root_path, alert: params[:message]
  end

  def destroy
    reset_session
    redirect_to root_path
  end
end
