Rails.application.routes.draw do
  root 'home#index'
  get 'auth/google_oauth2/callback' => 'auth_callbacks#google'
  resource :session, only: %i[destroy]
end
