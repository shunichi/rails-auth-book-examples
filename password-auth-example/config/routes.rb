Rails.application.routes.draw do
  root 'home#index'
  resource :registration, only: %i[new create]
  resource :session, only: %i[new create destroy]
end
