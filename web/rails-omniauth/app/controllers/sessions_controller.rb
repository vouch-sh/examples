class SessionsController < ApplicationController
  def index
    render inline: <<~HTML
      <!DOCTYPE html>
      <html>
      <head><title>Vouch + Rails</title></head>
      <body>
        <h1>Vouch OIDC + Rails + OmniAuth</h1>
        <% if current_user %>
          <p>Welcome, <%= current_user['name'] %></p>
          <p>Email: <%= current_user['email'] %></p>
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
    session[:user] = {
      'email' => auth.info.email,
      'name' => auth.info.name,
      'hardware_verified' => auth.extra.raw_info&.hardware_verified
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
