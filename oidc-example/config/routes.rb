Rails.application.routes.draw do
  # ログインリンクを配置するページ
  root 'home#index'
  # ログイン/ログアウト
  resource :session, only: %i[create destroy]
  # 認可サーバーで認証後のリダイレクト先
  get 'auth/google/callback' => 'auth_callbacks#google'
end
