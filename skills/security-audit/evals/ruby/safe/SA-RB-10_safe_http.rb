# SA-RB-10: safe HTTP fetching with Net::HTTP and URL validation
require 'net/http'
require 'uri'

ALLOWED_HOSTS = %w[api.example.com cdn.example.com].freeze

def fetch_content(url_string)
  uri = URI.parse(url_string)
  raise 'Invalid scheme' unless %w[http https].include?(uri.scheme)
  raise 'Host not allowed' unless ALLOWED_HOSTS.include?(uri.host)

  Net::HTTP.get(uri)
end

puts fetch_content(ARGV[0])
