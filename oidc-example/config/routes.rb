Rails.application.routes.draw do
  root 'home#index'

  get 'auth/google/callback' => 'auth_callbacks#google'
  resource :session, only: %i[create destroy]
end
