# frozen_string_literal: true

# Authorization Code Flow で認証(state使用)
module GoogleAuthWithState
  include GoogleAuthBase

  module_function

  def build_auth_url(session)
    # 不正アクセス防止用にランダムな state を生成し、 session に保存しておく
    # 認可サーバーからのリダイレクト時にも同じ state が渡されるので検証する
    state = SecureRandom.hex(32)
    session[:oauth_state] = state
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
      # CSRFで攻撃者の認可コードを使わせる攻撃を防ぐために state を渡す
      # http://openid-foundation-japan.github.io/rfc6749.ja.html#CSRF
      state: state,
    }
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
end
