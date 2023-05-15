# frozen_string_literal: true

# Authorization Code Flow with PKCE で認証
module GoogleAuthWithPkce
  include GoogleAuthBase

  module_function

  def build_auth_url(session)
    # code_verifier はランダムな URL-Safe Base64 で 43〜128文字
    code_verifier = SecureRandom.urlsafe_base64(64) # 32〜96 -> 43〜128
    # code_challenge_method == 'S256' のときは
    # code_challenge = BASE64URL-ENCODE(SHA256(ASCII(code_verifier))) と仕様で定義されている
    code_challenge = Base64.urlsafe_encode64(Digest::SHA256.digest(code_verifier), padding: false)
    code_challenge_method = 'S256'
    # code_verifier はセッションに保存しておく
    session[:code_verifier] = code_verifier

    auth_params = {
      # 一度同意済みでも同意画面を出す場合に prompt=concent を指定する
      prompt: 'consent',
      # GCPのプロジェクトで作成した「OAuthクライアントID」を環境変数に設定しておく
      client_id: ENV.fetch('GOOGLE_CLIENT_ID'),
      # 認可コードを受け取るアプリケーションのURL
      # GCPのプロジェクトのOAuth同意画面で設定したものと同じものを指定する
      redirect_uri: REDIRECT_URI,
      # アクセストークンでなく認可コード(code)を返してほしい
      # つまり Authorization Code Flow
      response_type: 'code',
      # OAuth 2.0 のアクセストークンスコープ
      # * openid - OpenID Connect の認証
      # * email - Googleアカウントのプライマリメールアドレスの取得
      # * profile - ユーザーの公開プロフィールの取得
      # https://developers.google.com/identity/protocols/oauth2/scopes#openid-connect
      scope: 'openid email profile',
      # code_challenge と code_challenge_method をパラメータとして渡すと PKCE が使われる
      code_challenge: code_challenge,
      code_challenge_method: code_challenge_method,
    }
    "#{AUTHENTICATION_ENDPOINT}?#{auth_params.to_query}"
  end

  def request_token(params, session)
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
      # code_challenge の元になった code_verifier を渡すと
      # トークンエンドポイントで code_challenge の計算が行われ、
      # 認可リクエスト時のパラメータと一致するかチェックされる
      code_verifier: session[:code_verifier],
      # わざとおかしな code_verifer を渡すと失敗するか試す場合は下の code_verifier を使う
      # code_verifier: SecureRandom.urlsafe_base64(32),
    }
    Rails.logger.info '------------------------ token request'
    Rails.logger.info JSON.pretty_generate(body)
    response = HttpUtil.post(TOKEN_ENDPOINT, body.to_query, headers)
    # レスポンスのJSONを解釈し必要な情報を取り出す
    TokenResponse.new(response.body)
  end
end
