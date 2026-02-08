require_relative 'boot'
require 'rails/all'

module VouchExample
  class Application < Rails::Application
    config.load_defaults 7.1
    config.secret_key_base = ENV.fetch('SECRET_KEY_BASE') { SecureRandom.hex(64) }
  end
end
