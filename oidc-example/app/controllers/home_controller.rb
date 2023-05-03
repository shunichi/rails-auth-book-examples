# frozen_string_literal: true

class HomeController < ApplicationController
  def index
    Rails.logger.info '------------------------ home request headers'
    Rails.logger.info JSON.pretty_generate(request.headers.to_h)
  end
end
