class AuthCallbacksController < ApplicationController
  def google
    user_info = request.env['omniauth.auth']
    Rails.logger.info JSON.pretty_generate(user_info.to_h)
    session[:uid] = user_info['uid']
    session[:user_name] = user_info.dig('info', 'name')
    session[:user_email] = user_info.dig('info', 'email')
    redirect_to root_url
  end
end
