class MyFaradayLogger < Faraday::Middleware
  def initialize(app)
    super
  end

  def call(env)
    log_request(env)
    super
  end

  def on_complete(env)
    log_response(env)
  end

  private

  def log_request(env)
    url = env.url
    http_method = env.method.to_s.upcase
    Rails.logger.info '----- Faraday Request: [%s] %s %s' % [url.host, http_method, url.request_uri]
    Rails.logger.info "-- request_headers:\n#{JSON.pretty_generate(env.request_headers)}"
    Rails.logger.info "-- request_body:\n#{env.request_body}" if env.method == :post
    Rails.logger.info '-----'
  end

  def log_response(env)
    Rails.logger.info "-- response_headers:\n#{JSON.pretty_generate(env.response_headers)}"
    Rails.logger.info "-- response_body:\n#{env.body}" if env.body.present?
    Rails.logger.info '-----'
  end
end

Rails.application.config.middleware.use OmniAuth::Builder do
  connection_build = proc do |builder|
    builder.request :url_encoded             # form-encode POST params
    builder.use MyFaradayLogger
    builder.adapter Faraday.default_adapter  # make requests with Net::HTTP
  end
  # provider :google_oauth2, ENV.fetch('GOOGLE_CLIENT_ID'), ENV.fetch('GOOGLE_CLIENT_SECRET')
  provider :google_oauth2, ENV.fetch('GOOGLE_CLIENT_ID'), ENV.fetch('GOOGLE_CLIENT_SECRET'), client_options: { connection_build: connection_build }
end
OmniAuth.config.allowed_request_methods = %i[post]
