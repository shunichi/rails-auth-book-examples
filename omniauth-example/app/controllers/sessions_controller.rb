# frozen_string_literal: true

class SessionsController < ApplicationController
  def destroy
    %i[uid user_name user_email].each do |key|
      session.delete(key)
    end
    redirect_to root_url
  end
end
