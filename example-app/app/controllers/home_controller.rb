class HomeController < ApplicationController
  def index
    session[:user_id] = 123
    render plain: 'OK'
  end

  private

  def decode_session
    encrypted_cookie_cipher = Rails.application.config.action_dispatch.encrypted_cookie_cipher || "aes-256-gcm"
    key_len = ActiveSupport::MessageEncryptor.key_len(encrypted_cookie_cipher)
    authenticated_encrypted_cookie_salt = Rails.application.config.action_dispatch.authenticated_encrypted_cookie_salt
    secret = Rails.application.key_generator.generate_key(authenticated_encrypted_cookie_salt, key_len)
    encryptor = ActiveSupport::MessageEncryptor.new(secret, cipher: encrypted_cookie_cipher, serializer: ActiveSupport::MessageEncryptor::NullSerializer)

    session_cookie_name = "_example_app_session"
    encrypted_message = cookies[session_cookie_name]
    return if encrypted_message.blank?
    purpose = "cookie.#{session_cookie_name}"
    decrypted = encryptor.decrypt_and_verify(encrypted_message, purpose: purpose)
    decoded = ActiveSupport::JSON.decode(decrypted)

    Rails.logger.info "sesssion: #{decoded.inspect}"
  end
end

3
2
