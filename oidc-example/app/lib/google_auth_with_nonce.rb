# Googleの公式ドキュメント https://developers.google.com/identity/openid-connect/openid-connect

module GoogleAuthWithNonce
  include GoogleAuthBase

  module_function

  def build_auth_url(session)
    raw_nonce = SecureRandom.hex(20)
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
      # IDトークンのリプレイ攻撃を防ぐための nonce
      # サーバーでトークンAPIを呼ぶ場合はトークンリプレイ攻撃は
      # できないのでその意味では不要。
      # ただし state と同様にCSRFを防ぐ意味がある。
      # nonce は生のランダム値を HttpOnly cookie に保存して、
      # パラメータとしては生の値の暗号学的ハッシュを渡す手法が
      # OpenID Connect の仕様で紹介されている。
      # http://openid-foundation-japan.github.io/openid-connect-core-1_0.ja.html#NonceNotes
      nonce: Digest::SHA256.hexdigest(raw_nonce),
    }
    session[:oidc_raw_nonce] = raw_nonce
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
      # 正しいクライアントアプリからのリクエストだと認証サーバーが判定するために必要
      client_secret: ENV.fetch('GOOGLE_CLIENT_SECRET'),
      redirect_uri: REDIRECT_URI,
      grant_type: 'authorization_code',
    }.to_query
    response = HttpUtil.post(TOKEN_ENDPOINT, body, headers)
    # 同じ nonce を二度使ってはいけないので session から削除するのがポイント
    TokenResponse.new(response.body, raw_nonce: session.delete(:oidc_raw_nonce))
  end
end
