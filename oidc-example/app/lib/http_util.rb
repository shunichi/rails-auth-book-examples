# frozen_string_literal: true

require 'net/http'

module HttpUtil
  module_function

  def get(url, headers = {})
    uri = URI.parse(url)
    http = Net::HTTP.new(uri.host, uri.port)
    http.use_ssl = uri.scheme == 'https'
    response = http.get(url, headers)
    raise_http_error('GET', url, response) unless response.code == '200'
    response
  end

  def post(url, body = nil, headers = {})
    uri = URI.parse(url)
    http = Net::HTTP.new(uri.host, uri.port)
    http.use_ssl = uri.scheme == 'https'
    response = http.post(url, body, headers)
    raise_http_error('POST', url, response) unless response.code == '200'
    response
  end

  def raise_http_error(http_method, url, response)
    raise "HTTP error: #{http_method} #{url}, status:#{response.code}, body: #{response.body}"
  end
end
