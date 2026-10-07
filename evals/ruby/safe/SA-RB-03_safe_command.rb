# SA-RB-03: safe command execution using Open3 with array form
require 'open3'

def ping_host(hostname)
  # Array form avoids shell interpretation entirely
  stdout, stderr, status = Open3.capture3('ping', '-c', '1', hostname)
  raise "Ping failed: #{stderr}" unless status.success?
  stdout
end

puts ping_host(ARGV[0])
