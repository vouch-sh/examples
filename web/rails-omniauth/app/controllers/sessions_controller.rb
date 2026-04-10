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

    # Hardware claims are in the access token JWT (RFC 9068), not the id_token.
    hardware_verified = false
    access_token = auth.credentials&.token
    if access_token
      parts = access_token.split('.')
      if parts.length == 3
        payload = JSON.parse(Base64.urlsafe_decode64(parts[1]))
        hardware_verified = payload['hardware_verified'] || false
      end
    end

    session[:user] = {
      'email' => auth.info.email,
      'hardware_verified' => hardware_verified
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
