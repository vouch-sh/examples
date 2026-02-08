Rails.application.routes.draw do
  root 'sessions#index'
  get '/auth/vouch/callback', to: 'sessions#create'
  get '/auth/failure', to: 'sessions#failure'
  delete '/logout', to: 'sessions#destroy'
end
