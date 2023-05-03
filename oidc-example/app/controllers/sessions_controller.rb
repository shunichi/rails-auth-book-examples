# frozen_string_literal: true

class SessionsController < ApplicationController
  def create
    Rails.logger.info '------------------------ sessions#create request headers'
    Rails.logger.info JSON.pretty_generate(request.headers.to_h)
    redirect_to GoogleAuth.build_auth_url(session), allow_other_host: true
  end

  def destroy
    %i[uid user_name].each do |key|
      session.delete(key)
    end
    redirect_to root_url
  end
end
