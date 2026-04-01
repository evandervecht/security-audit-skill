# SA-RB-05: safe YAML parsing with safe_load
require 'yaml'
require 'net/http'

def import_config(url)
  response = Net::HTTP.get(URI(url))
  config = YAML.safe_load(response, permitted_classes: [Date, Time])
  config
end

config = import_config(ARGV[0])
puts config.inspect
