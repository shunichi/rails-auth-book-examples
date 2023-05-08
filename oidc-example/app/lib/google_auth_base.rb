# frozen_string_literal: true

module GoogleAuthBase
  # これらのURLは https://accounts.google.com/.well-known/openid-configuration から
  # 得ることもできるが、ここでは直書きしている
  AUTHENTICATION_ENDPOINT = 'https://accounts.google.com/o/oauth2/auth'
  TOKEN_ENDPOINT = 'https://oauth2.googleapis.com/token'
  USERINFO_ENDPOINT = 'https://openidconnect.googleapis.com/v1/userinfo'
  JWKS_URI = 'https://www.googleapis.com/oauth2/v3/certs'

  # Google Cloud Platform で設定した「承認済みのリダイレクト URI」
  REDIRECT_URI = 'http://localhost:3000/auth/google/callback'

  module_function

  module ClassMethods
    def request_userinfo(access_token)
      headers = {
        'Authorization' => "Bearer #{access_token}"
      }
      response = HttpUtil.get(USERINFO_ENDPOINT, headers)
      JSON.parse(response.body)
    end
  end

  def self.included(mod)
    mod.extend ClassMethods
  end

  def fetch_jwks
    # 本当は Cache-Control ヘッダの値に従ってキャッシュすべきだが、複雑な実装になるのでこのサンプルでは毎回取得する
    response = HttpUtil.get(JWKS_URI)
    jwks = JWT::JWK::Set.new(JSON.parse(response.body))
    jwks.select { |key| key[:use] == 'sig' } # 署名検証用の鍵のみ
  end

  class TokenResponse
    attr_reader :raw, :id_token_payload, :id_token_header

    def initialize(response_body, raw_nonce: nil)
      @raw = JSON.parse(response_body)
      @raw_nonce = raw_nonce
      decode_id_token
    end

    %w[access_token expires_in refresh_token scope token_type id_token].each do |name|
      define_method name do
        @raw[name]
      end
    end

    private

    def decode_id_token
      # Google が Web で公開している JSON Web Key Set (JWKS) を取得
      jwks = GoogleAuthBase.fetch_jwks
      # JWKS から署名に使われる暗号アルゴリズムを取得
      algorithms = jwks.map { |key| key[:alg] }.compact.uniq
      # IDトークンの署名を JWKS で検証しデコードする
      @id_token_payload, @id_token_header =
        JWT.decode(
          id_token,
          nil,
          true,
          algorithms: algorithms,
          jwks: jwks
        )
      # 他のアプリケーションに対して発行された認可コードが送られてくる攻撃を防ぐため
      # IDトークンの発行対象をチェックする
      # aud は Google の場合クライアントIDと一致する
      if @id_token_payload['aud'] != ENV.fetch('GOOGLE_CLIENT_ID')
        raise 'ID Token error: invalid aud!'
      end
      if @id_token_payload['nonce']
        raise 'ID Token error: missing session nonce!' if @raw_nonce.nil?
        if @id_token_payload['nonce'] != Digest::SHA256.hexdigest(@raw_nonce)
          raise 'ID Token error: nonce mismatch!'
        end
      end
    end

    # ID Token の検証が行われていることの確認用にわざとエラーの起きるIDトークンを作る
    def id_token_with_error
      raw_id_token = id_token.dup
      header, payload, signature = raw_id_token.split('.')
      decoded_signature = Base64.urlsafe_decode64(signature)
      [header, payload, Base64.urlsafe_encode64(decoded_signature.split('').shuffle.join)].join('.')
    end
  end
end
