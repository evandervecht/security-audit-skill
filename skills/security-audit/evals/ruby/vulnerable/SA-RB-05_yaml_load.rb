# SA-RB-05: YAML.load on untrusted input — insecure deserialization
require 'yaml'
require 'net/http'

def import_config(url)
  response = Net::HTTP.get(URI(url))
  config = YAML.load(response)
  config
end

# Attacker hosts YAML with "--- !ruby/object:Gem::Installer" payload
config = import_config(ARGV[0])
puts config.inspect
