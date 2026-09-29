require_relative 'boot'
require 'rails/all'
Bundler.require(*Rails.groups)

module VouchExample
  class Application < Rails::Application
    config.load_defaults 8.0
    config.eager_load = false
    # Signs and encrypts the session cookie, which holds the ID token. No fallback: a
    # random per-process key would silently sign everyone out on every restart.
    config.secret_key_base = ENV['SECRET_KEY_BASE'].presence ||
                             raise('SECRET_KEY_BASE is required')
  end
end
