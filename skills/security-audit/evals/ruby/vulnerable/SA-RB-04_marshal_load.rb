# SA-RB-04: Marshal.load on untrusted data — insecure deserialization
require 'base64'

def restore_session(cookie_value)
  data = Base64.decode64(cookie_value)
  session = Marshal.load(data)
  session
end

# Attacker crafts a malicious serialized payload
session = restore_session(ENV['SESSION_COOKIE'])
puts session.inspect
