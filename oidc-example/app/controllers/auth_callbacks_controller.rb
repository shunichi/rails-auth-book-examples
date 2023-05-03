# frozen_string_literal: true

class AuthCallbacksController < ApplicationController
  def google
    # キャンセルしたとき
    # http://localhost:3000/auth/google/callback?error=access_denied&state=f466a88d53bc912f818a3fc7457be92b0c4c7229

    Rails.logger.info '------------------------ callback params'
    Rails.logger.info JSON.pretty_generate(params.to_unsafe_h)

    Rails.logger.info '------------------------ callback request headers'
    Rails.logger.info JSON.pretty_generate(request.headers.to_h)

    # クエリパラメータに入っている code (認可コード) を使ってトークンを取得する
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

    # 認証のデモなのでDBに保存せず session に保存するだけですませる
    session[:uid] = token_response.id_token_payload['sub']
    session[:user_name] = token_response.id_token_payload['name']

    redirect_to root_url
  end
end
