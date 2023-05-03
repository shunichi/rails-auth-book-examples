# frozen_string_literal: true

# Googleの公式ドキュメント https://developers.google.com/identity/openid-connect/openid-connect
module GoogleAuth
  AUTHENTICATION_ENDPOINT = 'https://accounts.google.com/o/oauth2/auth'
  TOKEN_ENDPOINT = 'https://oauth2.googleapis.com/token'
  USERINFO_ENDPOINT = 'https://openidconnect.googleapis.com/v1/userinfo'
  JWKS_URI = 'https://www.googleapis.com/oauth2/v3/certs'

  REDIRECT_URI = 'http://localhost:3000/auth/google/callback'

  module_function

  def build_auth_url(session)
    state = SecureRandom.hex(20)
    auth_params = {
      # 一度同意済みでも同意画面を出す場合に prompt=concent を指定する
      prompt: 'consent',
      # GCPのプロジェクトで作成した「OAuthクライアントID」を環境変数に設定しておく
      client_id: ENV.fetch('GOOGLE_CLIENT_ID'),
      # 認可コードを受け取るアプリケーションのURL
      # GCPのプロジェクトのOAuth同意画面で設定したものと同じものを指定する
      redirect_uri: REDIRECT_URI,
      # アクセストークンそのものでなく認可コードを返してほしい
      # つまり Authorization Code Flow
      response_type: 'code',
      # OAuth 2.0 のアクセストークンスコープ
      # * openid - OpenID Connect の認証
      # * email - Googleアカウントのプライマリメールアドレスの取得
      # * profile - ユーザーの公開プロフィールの取得
      # https://developers.google.com/identity/protocols/oauth2/scopes#openid-connect
      scope: 'openid email profile',
      # CSRFで攻撃者の認可コードを使わせる攻撃を防ぐために state を渡す
      # http://openid-foundation-japan.github.io/rfc6749.ja.html#CSRF
      state:,
    }
    session[:oauth_state] = state
    "#{AUTHENTICATION_ENDPOINT}?#{auth_params.to_query}"
  end

  def request_token(params, session)
    # 攻撃者が標的ユーザーに自分の認可コードを使わせる攻撃をチェックする
    # 不正な認可コードが送られてきた場合は session に対応する
    # state が入っていないため検出できる
    unless session.delete(:oauth_state) == params[:state]
      raise 'Invalid OAuth state'
    end

    headers = { 'Content-Type' => 'application/x-www-form-urlencoded' }
    body = {
      # 認可サーバーから渡された認可コード
      code: params[:code],
      # GCPで取得したクライアントID
      client_id: ENV.fetch('GOOGLE_CLIENT_ID'),
      # GCPで取得したクライアントシークレット
      # 正しいクライアントアプリからのリクエストの判別に使われる
      client_secret: ENV.fetch('GOOGLE_CLIENT_SECRET'),
      # 認可リクエストで認可サーバーに送られたのと同じ redirect_uri
      redirect_uri: REDIRECT_URI,
      # Authorization Code Flow を表す
      grant_type: 'authorization_code',
    }.to_query
    response = HttpUtil.post(TOKEN_ENDPOINT, body, headers)
    # レスポンスのJSONを解釈し必要な情報を取り出す
    TokenResponse.new(response.body)
  end

  def request_userinfo(access_token)
    headers = {
      'Authorization' => "Bearer #{access_token}"
    }
    response = HttpUtil.get(USERINFO_ENDPOINT, headers)
    JSON.parse(response.body)
  end

  class TokenResponse
    attr_reader :raw, :id_token_payload, :id_token_header

    def initialize(response_body)
      @raw = JSON.parse(response_body)
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
      jwks = GoogleAuth.fetch_jwks
      # JWKS から署名に使われる暗号アルゴリズムを取得
      algorithms = jwks.map { |key| key[:alg] }.compact.uniq
      # IDトークンの署名を JWKS で検証しデコードする
      @id_token_payload, @id_token_header =
        JWT.decode(
          id_token,
          nil,
          true,
          algorithms:,
          jwks:
        )
    end
  end

  def fetch_jwks
    # 本当は Cache-Control ヘッダの値に従ってキャッシュすべきだが、複雑な実装になるのでこのサンプルでは毎回取得する
    response = HttpUtil.get(JWKS_URI)
    jwks = JWT::JWK::Set.new(JSON.parse(response.body))
    jwks.select! { |key| key[:use] == 'sig' } # Signing Keys only
    jwks
  end
end
