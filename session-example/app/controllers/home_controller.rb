class HomeController < ApplicationController
  def index
    if params[:write]
      store_session(
        session_id: SecureRandom.hex(16),
        message: 'これは自作の store_session で書き込んだメッセージです'
      )
      redirect_to root_url
    elsif params[:reset]
      reset_session
      redirect_to root_url
    else
      session[:user_id] = 123
    end
    @session_data = load_session
  end

  private

  def load_session
    # Cookie のキー (_アプリ名_session)
    session_cookie_name = "_example_app_session"
    # Cookie の値を読む
    encrypted_message = cookies[session_cookie_name]
    return {} if encrypted_message.blank?

    # 暗号化方式
    encrypted_cookie_cipher = "aes-256-gcm"
    # 鍵の生成用パラメータ
    salt = "authenticated encrypted cookie"
    key_len = ActiveSupport::MessageEncryptor.key_len(encrypted_cookie_cipher)
    # secret_key_base を使って暗号化の鍵を作る
    secret = Rails.application.key_generator.generate_key(salt, key_len)
    # OpenSSL をラップした暗号化/復号するクラスのインスタンスを生成
    encryptor = ActiveSupport::MessageEncryptor.new(
      secret,
      cipher: encrypted_cookie_cipher,
      serializer: ActiveSupport::MessageEncryptor::NullSerializer
    )

    # 復号
    decrypted = encryptor.decrypt_and_verify(
      encrypted_message,
      purpose: "cookie.#{session_cookie_name}"
    )
    # 復号したJSON文字列を Ruby の Hash に変換
    ActiveSupport::JSON.decode(decrypted)
  end

  def store_session(session_data)
    # encryptor の生成コードは復号処理と同じ
    encrypted_cookie_cipher = "aes-256-gcm"
    salt = "authenticated encrypted cookie"
    key_len = ActiveSupport::MessageEncryptor.key_len(encrypted_cookie_cipher)
    secret = Rails.application.key_generator.generate_key(salt, key_len)
    encryptor = ActiveSupport::MessageEncryptor.new(
      secret,
      cipher: encrypted_cookie_cipher,
      serializer: ActiveSupport::MessageEncryptor::NullSerializer
    )

    # Ruby の Hash をJSON文字列に変換
    encoded = ActiveSupport::JSON.encode(session_data)
    # Cookie のキー (_アプリ名_session)
    session_cookie_name = "_example_app_session"
    # 暗号化
    encrypted = encryptor.encrypt_and_sign(
      encoded,
      purpose: "cookie.#{session_cookie_name}"
    )
    # Cookie への書き出し
    cookies[session_cookie_name] = {
      value: encrypted,
      path: '/',
      httponly: true,
      secure: false, # https のときは true
    }
  end
end
