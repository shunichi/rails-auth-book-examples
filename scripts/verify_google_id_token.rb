# googleのIDトークンの署名検証してペイロードを標準出力に出力するプログラム
#
# 使い方: ruby verify_google_id_token.rb IDトークン文字列

require 'net/http'
require 'json'
require 'openssl'
require 'base64'

# JWKS は次のようなJSON
#
# {
#   "keys": [
#     {
#       "e": "AQAB",
#       "use": "sig",
#       "n": "t0VFy4n4MGtbMWJKk5qfCY2WGBja2WSWQ2zsLziSx9p1QE0QgXtr1x85PnQYaYrAvOBiXm2mrxWnZ42MxaUUu9xyykTDxsNWHK--ufchdaqJwfqd5Ecu-tHvFkMIs2g39pmG8QfXJHKMqczKrvcHHJrpTqZuos1uhYM9gxOLVP8wTAUPNqa1caiLbsszUC7yaMO3LY1WLQST79Z8u5xttKXShXFv1CCNs8-7vQ1IB5DWQSR2um1KV4t42d31Un4-8cNiURx9HmJNJzOXbTG-vDeD6sapFf5OGDsCLO4YvzzkzTsYBIQy_p88qNX0a6AeU13enxhbasSc-ApPqlxBdQ",
#       "kid": "c9afda3682ebf09eb3055c1c4bd39b751fbf8195",
#       "alg": "RS256",
#       "kty": "RSA"
#     },
#     {
#       "use": "sig",
#       "alg": "RS256",
#       "kty": "RSA",
#       "n": "z4MmKRO3SVa_U6P1htjsIUmNue3NKrtfOBaOPeI1xFHMoI62S5mkvOuSkZNDT22sILYFWUv4ToLm9vsp7RqDF9fLhhLBwLHw8LJUf4lxFZ8DYnu2-LB0EWbOHktvj0CIzAWdTIzqusEUZE9vzxo5p0SxrghzpvIgAx0U-RoqnbnT6t4XGBTYEVysIVUeO8PmCGPYtCDdwRRJ4lyVYfMThWoE4CCkDq-cffT2l4PgDwNpsyc1z-7k3luXZ__ARG2M6GFoJ4IrhG-tzTOBJdirCFxP7A5jrAexMERyQQbHeZRCaGXWMy_YaoPOi1nspeqvjIZiq9MZrgXmmnC0wvUzYQ",
#       "kid": "7770b085bf649b726b3574764030e1bde9a10ae6",
#       "e": "AQAB"
#     }
#   ]
# }
def fetch_google_jwks
  # OpenID Provider Configuration Document にある jwks_uri のURLから JWKS が得られます
  # https://accounts.google.com/.well-known/openid-configuration をブラウザで開いてみてください
  jwks_uri = 'https://www.googleapis.com/oauth2/v3/certs'
  response = Net::HTTP.get_response(URI.parse(jwks_uri))
  JSON.parse(response.body)
end

# JSON Web Key Set から署名検証に使う鍵を探す
def find_jwk(jwks, kid)
  jwks['keys'].find { |key| key['kid'] == kid }
  raise 'Key not found' if jwk.nil?
end

def decode_openssl_bn(jwk_data)
  OpenSSL::BN.new(Base64.urlsafe_decode64(jwk_data), 2)
end

# JSON Web Key から RSA の鍵を生成する
def build_rsa_key(jwk)
  raise 'Unsupported key type' if jwk['kty'] != 'RSA'
  raise 'Insufficient key parameters' unless jwk['n'] && jwk['e']

  sequence = OpenSSL::ASN1::Sequence(
    [
      OpenSSL::ASN1::Integer.new(decode_openssl_bn(jwk['n'])),
      OpenSSL::ASN1::Integer.new(decode_openssl_bn(jwk['e'])),
    ]
  )
  OpenSSL::PKey::RSA.new(OpenSSL::ASN1::Sequence(sequence).to_der)
end

def verify_id_token(id_token, jwks)
  encoded_header, encoded_payload, encoded_signature = id_token.split('.')
  # IDトークンのヘッダは以下のようなJSON
  # {
  #   "alg": "RS256",
  #   "kid": "c9afda3682ebf09eb3055c1c4bd39b751fbf8195",
  #   "typ": "JWT"
  # }
  header = JSON.parse(Base64.urlsafe_decode64(encoded_header))
  signature = Base64.urlsafe_decode64(encoded_signature)

  jwk = find_jwk(jwks, header['kid'])

  rsa_key = build_rsa_key(jwk)
  data = [encoded_header, encoded_payload].join('.')
  # alg = RSA256 なら sha256 で署名検証する
  hash_func_name = jwk['alg'].sub('RS', 'sha')
  rsa_key.verify(hash_func_name, signature, data)
end

def print_payload(id_token)
  _, encoded_payload, = id_token.split('.')
  payload = JSON.parse(Base64.urlsafe_decode64(encoded_payload))
  puts JSON.pretty_generate(payload)
end

id_token = ARGV.shift
if verify_id_token(id_token, fetch_google_jwks)
  print_payload(id_token)
else
  puts 'Failed to verify signature'
  exit 1
end
