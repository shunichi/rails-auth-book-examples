class AuthCallbacksController < ApplicationController
  def google
    Rails.logger.info '------------------------ callback params'
    Rails.logger.info JSON.pretty_generate(params.to_unsafe_h)

    token_response = GoogleAuth.request_token(params, session)
    userinfo = GoogleAuth.request_userinfo(token_response.access_token)

    Rails.logger.info '------------------------ token response'
    Rails.logger.info JSON.pretty_generate(token_response.raw)
    Rails.logger.info '------------------------ id_token header'
    Rails.logger.info JSON.pretty_generate(token_response.id_token_header)
    Rails.logger.info '------------------------ id_token payload'
    Rails.logger.info JSON.pretty_generate(token_response.id_token_payload)
    Rails.logger.info '------------------------ userinfo'
    Rails.logger.info JSON.pretty_generate(userinfo)

    session[:uid] = token_response.id_token_payload['sub']
    session[:user_name] = token_response.id_token_payload['name']
    session[:user_email] = token_response.id_token_payload['email']
    redirect_to root_url
  end
end
