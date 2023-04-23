class SessionsController < ApplicationController
  def create
    redirect_to GoogleAuth.build_auth_url(session), allow_other_host: true
  end

  def destroy
    %i[uid user_name user_email].each do |key|
      session.delete(key)
    end
    redirect_to root_url
  end
end
