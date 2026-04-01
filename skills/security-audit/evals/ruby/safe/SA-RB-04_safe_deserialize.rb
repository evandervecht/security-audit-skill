# SA-RB-04: safe deserialization using JSON instead of Marshal
require 'json'
require 'base64'

def restore_session(cookie_value)
  data = Base64.decode64(cookie_value)
  session = JSON.parse(data)
  session
end

session = restore_session(ENV['SESSION_COOKIE'])
puts session.inspect
